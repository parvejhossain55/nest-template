import {
  ConflictException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { Prisma, Role, TokenType, User, UserStatus } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { PrismaService } from 'src/database/prisma/prisma.service';
import { MailService } from 'src/shared/mail/mail.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from './types/jwt-payload.types';

const BCRYPT_SALT_ROUNDS = 10;
const EMAIL_VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const TOKEN_BYTES = 32; // raw verification tokens are random 64-char hex strings

type ExpiresIn = JwtSignOptions['expiresIn'];

/** Internal sentinel: the refresh-token claim lost to a concurrent rotation. */
class RefreshRotationConflict extends Error {}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
  ) {}

  async register(dto: RegisterDto) {
    const email = dto.email.toLowerCase().trim();

    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new ConflictException('Email is already registered');
    }

    const hashedPassword = await bcrypt.hash(dto.password, BCRYPT_SALT_ROUNDS);

    let user: User;
    try {
      user = await this.prisma.user.create({
        data: { email, passwordHash: hashedPassword, name: dto.name ?? null },
      });
    } catch (error) {
      // The unique-email race can slip past the check above; map it to 409.
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Email is already registered');
      }
      throw error;
    }

    // Best-effort welcome email — never block signup on SMTP (which can hang
    // for minutes when the provider is unreachable). Fire-and-forget.
    const verificationUrl = await this.buildEmailVerificationUrl(user);
    void this.mailService
      .sendWelcomeEmail(user.email, user.name ?? 'there', verificationUrl)
      .catch((error) =>
        this.logger.warn(
          `Welcome email to ${user.email} failed: ${(error as Error).message}`,
        ),
      );

    const { expiresAt, accessToken, refreshToken } =
      await this.generateTokens(user);
    await this.storeRefreshToken(user.id, refreshToken, expiresAt);

    return {
      user: this.sanitizeUser(user),
      accessToken,
      refreshToken,
      expiresAt,
    };
  }

  async login(dto: LoginDto) {
    const email = dto.email.toLowerCase().trim();

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || user.deletedAt) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // OAuth-only accounts have no password hash and cannot sign in this way.
    if (!user.passwordHash) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordMatches = await bcrypt.compare(
      dto.password,
      user.passwordHash,
    );
    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw new UnauthorizedException('Account is not active');
    }

    // Best-effort: record the login time, never block sign-in on failure.
    await this.prisma.user
      .update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      })
      .catch((error: Error) =>
        this.logger.warn(
          `Failed to update lastLoginAt for ${user.email}: ${error.message}`,
        ),
      );

    const { expiresAt, accessToken, refreshToken } =
      await this.generateTokens(user);
    await this.storeRefreshToken(user.id, refreshToken, expiresAt);

    return {
      user: this.sanitizeUser(user),
      accessToken,
      refreshToken,
      expiresAt,
    };
  }

  async refresh(refreshToken: string) {
    let payload: JwtPayload;
    try {
      payload = await this.jwtService.verifyAsync<JwtPayload>(refreshToken, {
        secret: this.configService.get<string>('jwt.refreshSecret'),
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const stored = await this.prisma.refreshToken.findUnique({
      where: { tokenHash: this.tokenDigest(refreshToken) },
      include: { user: true },
    });

    if (
      !stored ||
      stored.user.deletedAt ||
      stored.user.status !== UserStatus.ACTIVE
    ) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Tampering — the JWT subject must match the stored row.
    if (payload.sub !== stored.userId) {
      await this.revokeUserSessions(stored.userId);
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Merely expired is normal lifecycle — no theft signal, just reject.
    if (stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // A token that was already rotated is being replayed — kill the family.
    if (stored.revokedAt) {
      await this.revokeUserSessions(stored.userId);
      throw new UnauthorizedException('Invalid refresh token');
    }

    try {
      // Atomically claim the token and insert its successor in one transaction:
      // exactly one concurrent request wins the rotation, and a failure
      // mid-rotation rolls back instead of stranding the user.
      return await this.prisma.$transaction(async (tx) => {
        const claimed = await tx.refreshToken.updateMany({
          where: {
            tokenHash: this.tokenDigest(refreshToken),
            revokedAt: null,
            expiresAt: { gt: new Date() },
          },
          data: { revokedAt: new Date(), lastUsedAt: new Date() },
        });

        if (claimed.count !== 1) {
          // The same token was presented concurrently — treat it as replay.
          throw new RefreshRotationConflict();
        }

        const tokens = await this.generateTokens(stored.user);
        await tx.refreshToken.create({
          data: {
            userId: stored.userId,
            tokenHash: this.tokenDigest(tokens.refreshToken),
            expiresAt: tokens.expiresAt,
          },
        });

        return tokens;
      });
    } catch (error) {
      // Revoke the whole family on replay. Done outside the transaction so the
      // revocation is not rolled back with the failed claim. Genuine failures
      // (e.g. DB errors) propagate as-is instead of masquerading as a 401.
      if (error instanceof RefreshRotationConflict) {
        await this.revokeUserSessions(stored.userId);
        throw new UnauthorizedException('Invalid refresh token');
      }
      throw error;
    }
  }

  async getMe(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.deletedAt) {
      throw new UnauthorizedException('User not found');
    }

    return this.sanitizeUser(user);
  }

  async logout(refreshToken: string) {
    // Idempotent: revoking a session that no longer exists is still a success.
    await this.prisma.refreshToken.updateMany({
      where: { tokenHash: this.tokenDigest(refreshToken), revokedAt: null },
      data: { revokedAt: new Date() },
    });

    return { message: 'Logged out successfully' };
  }

  /**
   * Issues a fresh verification link. Returns a generic message whether or not
   * the email exists so the endpoint can't be used to enumerate registrations.
   */
  async resendVerification(email: string) {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
    });

    if (!user || user.deletedAt || user.emailVerifiedAt) {
      return {
        message: 'If this email is registered and unverified, a new link has been sent.',
      };
    }

    const verificationUrl = await this.buildEmailVerificationUrl(user);
    void this.mailService
      .sendWelcomeEmail(user.email, user.name ?? 'there', verificationUrl)
      .catch((error) =>
        this.logger.warn(
          `Verification email to ${user.email} failed: ${(error as Error).message}`,
        ),
      );

    return {
      message: 'If this email is registered and unverified, a new link has been sent.',
    };
  }

  async verifyEmail(token: string) {
    const verificationToken = await this.prisma.verificationToken.findUnique({
      where: { tokenHash: this.tokenDigest(token) },
      include: { user: true },
    });

    if (
      !verificationToken ||
      verificationToken.type !== TokenType.EMAIL_VERIFY ||
      verificationToken.usedAt ||
      verificationToken.expiresAt < new Date() ||
      verificationToken.user.deletedAt
    ) {
      throw new UnauthorizedException('Invalid or expired verification token');
    }

    const { user } = verificationToken;

    await this.prisma.$transaction([
      this.prisma.verificationToken.update({
        where: { id: verificationToken.id },
        data: { usedAt: new Date() },
      }),
      ...(user.emailVerifiedAt
        ? []
        : [
            this.prisma.user.update({
              where: { id: user.id },
              data: { emailVerifiedAt: new Date() },
            }),
          ]),
    ]);

    return { message: 'Email verified successfully' };
  }

  private async generateTokens(user: {
    id: string;
    email: string;
    role: Role;
  }) {
    // `jti` makes every token unique even when two tokens are signed within the
    // same second (JWT `iat` has 1s resolution and the payload is identical), so
    // the unique token_hash index can never see a collision.
    const payload: JwtPayload & { jti: string } = {
      sub: user.id,
      email: user.email,
      role: user.role,
      jti: randomUUID(),
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('jwt.accessSecret'),
        expiresIn: this.configService.get<ExpiresIn>(
          'jwt.accessExpiresIn',
          '15m',
        ),
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('jwt.refreshSecret'),
        expiresIn: this.configService.get<ExpiresIn>(
          'jwt.refreshExpiresIn',
          '7d',
        ),
      }),
    ]);

    // Read the `exp` claim from the freshly-minted token so the stored row's
    // expiry always matches the JWT lifetime.
    const decoded = await this.jwtService.verifyAsync<
      JwtPayload & { exp: number }
    >(refreshToken, {
      secret: this.configService.get<string>('jwt.refreshSecret'),
    });

    return {
      accessToken,
      refreshToken,
      expiresAt: new Date(decoded.exp * 1000),
    };
  }

  private async buildEmailVerificationUrl(user: { id: string; email: string }) {
    const appUrl = this.configService.get<string>(
      'appUrl',
      'http://localhost:3000',
    );
    const rawToken = randomBytes(TOKEN_BYTES).toString('hex');
    const expiresAt = new Date(Date.now() + EMAIL_VERIFICATION_TTL_MS);

    await this.prisma.verificationToken.create({
      data: {
        userId: user.id,
        tokenHash: this.tokenDigest(rawToken),
        type: TokenType.EMAIL_VERIFY,
        expiresAt,
      },
    });

    return `${appUrl}/auth/verify-email?token=${rawToken}`;
  }

  /**
   * Revokes every live refresh session for a user — used when a rotated token
   * is replayed (theft indicator) so a stolen token can't outlive its sibling
   * sessions.
   */
  private async revokeUserSessions(userId: string) {
    await this.prisma.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  private async storeRefreshToken(
    userId: string,
    refreshToken: string,
    expiresAt: Date,
  ) {
    await this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash: this.tokenDigest(refreshToken),
        expiresAt,
      },
    });
  }

  /**
   * Tokens are stored as a deterministic SHA-256 digest so they can be looked
   * up via the unique index and token reuse is detected.
   */
  private tokenDigest(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private sanitizeUser(user: User) {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      avatarUrl: user.avatarUrl,
      emailVerifiedAt: user.emailVerifiedAt,
      isTwoFactorEnabled: user.isTwoFactorEnabled,
      createdAt: user.createdAt,
    };
  }
}
