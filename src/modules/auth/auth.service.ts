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
import { CacheService } from 'src/shared/cache/cache.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from './types/jwt-payload.types';

const BCRYPT_SALT_ROUNDS = 10;
const EMAIL_VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000;
const TOKEN_BYTES = 32; // raw verification tokens are random 64-char hex strings
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const MAX_SESSIONS_PER_USER = 10;

type ExpiresIn = JwtSignOptions['expiresIn'];

/** Non-identifying context recorded against a refresh session for theft triage. */
export interface SessionMetadata {
  userAgent?: string;
  ipAddress?: string;
}

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
    private readonly cacheService: CacheService,
  ) {}

  async register(dto: RegisterDto, meta?: SessionMetadata) {
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

    const { expiresAt, accessToken, refreshToken } = await this.generateTokens(user);
    await this.storeRefreshToken(user.id, refreshToken, expiresAt, meta);

    return {
      user: this.sanitizeUser(user),
      accessToken,
      refreshToken,
      expiresAt,
    };
  }

  async login(dto: LoginDto, meta?: SessionMetadata) {
    const email = dto.email.toLowerCase().trim();
    const lockoutKey = this.cacheService.buildKey('throttle:login', email);

    // Check if the account is locked out from too many failed attempts.
    const failedAttempts = (await this.cacheService.get<number>(lockoutKey)) ?? 0;
    if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
      // Use the same generic message to prevent account-lockout enumeration.
      throw new UnauthorizedException('Invalid credentials');
    }

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
      // Track the failed attempt; auto-expires after the lockout window.
      await this.cacheService.set(
        lockoutKey,
        failedAttempts + 1,
        LOGIN_LOCKOUT_MS,
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // Successful login — clear any failed attempt counter.
    if (failedAttempts > 0) {
      await this.cacheService.del(lockoutKey);
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

    // Opportunistic upkeep: purge sessions that expired over a month ago so the
    // table doesn't grow unbounded. Recent history is kept for reuse detection.
    await this.prisma.refreshToken
      .deleteMany({
        where: {
          expiresAt: { lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
        },
      })
      .catch((error: Error) =>
        this.logger.warn(`Failed to purge expired sessions: ${error.message}`),
      );

    const { expiresAt, accessToken, refreshToken } =
      await this.generateTokens(user);
    await this.storeRefreshToken(user.id, refreshToken, expiresAt, meta);

    return {
      user: this.sanitizeUser(user),
      accessToken,
      refreshToken,
      expiresAt,
    };
  }

  async refresh(refreshToken: string, meta?: SessionMetadata) {
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
      this.logger.warn(
        `Refresh token subject mismatch for user ${stored.userId}; revoking all sessions`,
      );
      await this.revokeUserSessions(stored.userId);
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Merely expired is normal lifecycle — no theft signal, just reject.
    if (stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // A token that was already rotated is being replayed — a definite theft
    // signal; kill the whole family.
    if (stored.revokedAt) {
      this.logger.warn(
        `Refresh token reuse detected for user ${stored.userId}; revoking all sessions`,
      );
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
          // Another request already consumed this token — a concurrent refresh
          // or a client retry. Rotation already makes it single-use, so just
          // reject; revoking the whole family here would punish retries.
          throw new RefreshRotationConflict();
        }

        const tokens = await this.generateTokens(stored.user);
        await tx.refreshToken.create({
          data: {
            userId: stored.userId,
            tokenHash: this.tokenDigest(tokens.refreshToken),
            expiresAt: tokens.expiresAt,
            userAgent: meta?.userAgent,
            ipAddress: meta?.ipAddress,
          },
        });

        return tokens;
      });
    } catch (error) {
      // Genuine failures (e.g. DB errors) propagate as-is instead of
      // masquerading as a 401. Replay/conflict becomes a plain 401.
      if (error instanceof RefreshRotationConflict) {
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

  async verifyEmail(token: string) {
    const verificationToken = await this.prisma.verificationToken.findUnique({
      where: { tokenHash: this.tokenDigest(token) },
      // include: { user: true },
      select: {
        id: true,
        type: true,
        usedAt: true,
        expiresAt: true,
        user: {
          select: {
            id: true,
            emailVerifiedAt: true,
            deletedAt: true
          }
        }
      }
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
  private async revokeUserSessions(
    userId: string,
    excludeTokenHash?: string,
  ) {
    const where: Prisma.RefreshTokenWhereInput = {
      userId,
      revokedAt: null,
    };

    // When a token hash is provided, exclude it from revocation so the
    // caller's current session stays alive (e.g. after changePassword).
    if (excludeTokenHash) {
      where.tokenHash = { not: excludeTokenHash };
    }

    await this.prisma.refreshToken.updateMany({
      where,
      data: { revokedAt: new Date() },
    });
  }

  private async storeRefreshToken(
    userId: string,
    refreshToken: string,
    expiresAt: Date,
    meta?: SessionMetadata,
  ) {
    await this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash: this.tokenDigest(refreshToken),
        expiresAt,
        userAgent: meta?.userAgent,
        ipAddress: meta?.ipAddress,
      },
    });

    // Enforce per-user session limit: revoke the oldest sessions that push
    // the count above MAX_SESSIONS_PER_USER.
    const activeCount = await this.prisma.refreshToken.count({
      where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
    });

    if (activeCount > MAX_SESSIONS_PER_USER) {
      const excess = activeCount - MAX_SESSIONS_PER_USER;
      const oldestTokens = await this.prisma.refreshToken.findMany({
        where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
        orderBy: { createdAt: 'asc' },
        take: excess,
        select: { id: true },
      });

      if (oldestTokens.length > 0) {
        await this.prisma.refreshToken.updateMany({
          where: { id: { in: oldestTokens.map((t) => t.id) } },
          data: { revokedAt: new Date() },
        });
        this.logger.debug(
          `Revoked ${oldestTokens.length} oldest session(s) for user ${userId} (limit: ${MAX_SESSIONS_PER_USER})`,
        );
      }
    }
  }

  /**
   * Tokens are stored as a deterministic SHA-256 digest so they can be looked
   * up via the unique index and token reuse is detected.
   */
  private tokenDigest(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  async forgotPassword(email: string) {
    const normalizedEmail = email.toLowerCase().trim();

    // Per-email rate limit: max 3 reset requests per email per hour.
    const throttleKey = this.cacheService.buildKey('throttle:pwd-reset', normalizedEmail);
    const attempts = (await this.cacheService.get<number>(throttleKey)) ?? 0;
    if (attempts >= 3) {
      // Still return a generic message to prevent email enumeration.
      return {
        message: 'If this email is registered, a password reset link has been sent.',
      };
    }
    await this.cacheService.set(throttleKey, attempts + 1, 60 * 60 * 1000); // 1 hour TTL

    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    // Return a generic message to prevent email enumeration
    if (!user || user.deletedAt) {
      return {
        message: 'If this email is registered, a password reset link has been sent.',
      };
    }

    const appUrl = this.configService.get<string>(
      'appUrl',
      'http://localhost:3000',
    );
    const rawToken = randomBytes(TOKEN_BYTES).toString('hex');
    const PASSWORD_RESET_TTL_MS = 60 * 60 * 1000; // 1 hour
    const expiresAt = new Date(Date.now() + PASSWORD_RESET_TTL_MS);

    await this.prisma.verificationToken.create({
      data: {
        userId: user.id,
        tokenHash: this.tokenDigest(rawToken),
        type: TokenType.PASSWORD_RESET,
        expiresAt,
      },
    });

    const resetUrl = `${appUrl}/auth/reset-password?token=${rawToken}`;
    void this.mailService
      .sendPasswordResetEmail(user.email, user.name ?? 'there', resetUrl)
      .catch((error) =>
        this.logger.warn(
          `Password reset email to ${user.email} failed: ${(error as Error).message}`,
        ),
      );

    return {
      message: 'If this email is registered, a password reset link has been sent.',
    };
  }

  async resetPassword(token: string, newPassword: string) {
    const resetToken = await this.prisma.verificationToken.findUnique({
      where: { tokenHash: this.tokenDigest(token) },
      include: { user: true },
    });

    if (
      !resetToken ||
      resetToken.type !== TokenType.PASSWORD_RESET ||
      resetToken.usedAt ||
      resetToken.expiresAt < new Date() ||
      resetToken.user.deletedAt
    ) {
      throw new UnauthorizedException('Invalid or expired password reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

    await this.prisma.$transaction([
      this.prisma.verificationToken.update({
        where: { id: resetToken.id },
        data: { usedAt: new Date() },
      }),
      this.prisma.user.update({
        where: { id: resetToken.userId },
        data: { passwordHash: hashedPassword },
      }),
    ]);

    // Revoke all existing sessions after password change for security
    await this.revokeUserSessions(resetToken.userId);

    return { message: 'Password has been reset successfully' };
  }

  async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
    currentRefreshToken?: string,
  ) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.deletedAt) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.passwordHash) {
      throw new UnauthorizedException('Password is not set for this account');
    }

    const passwordMatches = await bcrypt.compare(oldPassword, user.passwordHash);
    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid current password');
    }

    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash: hashedPassword },
    });

    // Revoke all sessions except the current one so the user stays logged in.
    // A stolen session is still invalidated; only the caller's active session
    // survives by receiving a fresh refresh token below.
    const excludeHash = currentRefreshToken
      ? this.tokenDigest(currentRefreshToken)
      : undefined;
    await this.revokeUserSessions(userId, excludeHash);

    // Issue a new refresh token for the current session so the rotated-away
    // old token can never be replayed.
    const { expiresAt, accessToken, refreshToken } =
      await this.generateTokens(user);
    await this.storeRefreshToken(user.id, refreshToken, expiresAt);

    return {
      message: 'Password changed successfully',
      accessToken,
      refreshToken,
      expiresAt,
    };
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
      createdAt: user.createdAt,
    };
  }
}

