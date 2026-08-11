import {
  ConflictException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { Role, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { createHash } from 'node:crypto';
import { PrismaService } from 'src/database/prisma/prisma.service';
import { MailService } from 'src/shared/mail/mail.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from './types/jwt-payload.types';

const BCRYPT_SALT_ROUNDS = 10;
const EMAIL_VERIFICATION_TTL = '24h';

type ExpiresIn = JwtSignOptions['expiresIn'];

interface EmailVerificationPayload {
  sub: string;
  email: string;
  type: 'email-verification';
}

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

    const user = await this.prisma.user.create({
      data: { email, password: hashedPassword, name: dto.name },
    });

    // Best-effort welcome email — never block signup if the mail service fails.
    try {
      await this.mailService.sendWelcomeEmail(
        user.email,
        user.name ?? 'there',
        await this.buildVerificationUrl(user),
      );
    } catch (error) {
      this.logger.warn(
        `Welcome email to ${user.email} failed: ${(error as Error).message}`,
      );
    }

    const tokens = await this.generateTokens(user);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return { user: this.sanitizeUser(user), ...tokens };
  }

  async login(dto: LoginDto) {
    const email = dto.email.toLowerCase().trim();

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || user.deletedAt) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordMatches = await bcrypt.compare(dto.password, user.password);
    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is disabled');
    }

    const tokens = await this.generateTokens(user);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return { user: this.sanitizeUser(user), ...tokens };
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

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });
    if (!user || user.deletedAt || !user.isActive || !user.refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const storedMatches = await this.compareRefreshToken(
      refreshToken,
      user.refreshToken,
    );
    if (!storedMatches) {
      // Token reuse or tampering — revoke the session so it cannot be replayed.
      await this.prisma.user.update({
        where: { id: user.id },
        data: { refreshToken: null },
      });
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Rotation: each refresh issues a brand-new pair and invalidates the old one.
    const tokens = await this.generateTokens(user);
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  async logout(refreshToken: string) {
    // Idempotent: clearing a session that no longer exists is still a success.
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        refreshToken,
        { secret: this.configService.get<string>('jwt.refreshSecret') },
      );

      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
      });

      if (user?.refreshToken) {
        const matches = await this.compareRefreshToken(
          refreshToken,
          user.refreshToken,
        );
        if (matches) {
          await this.prisma.user.update({
            where: { id: user.id },
            data: { refreshToken: null },
          });
        }
      }
    } catch { } // Invalid/expired token — nothing to revoke from the client's perspective.

    return { message: 'Logged out successfully' };
  }

  async verifyEmail(token: string) {
    let payload: EmailVerificationPayload;
    try {
      payload = await this.jwtService.verifyAsync<EmailVerificationPayload>(
        token,
        {
          secret: this.configService.get<string>('jwt.accessSecret'),
        },
      );
    } catch {
      throw new UnauthorizedException('Invalid or expired verification token');
    }

    // Only tokens explicitly minted for email verification are accepted.
    if (payload.type !== 'email-verification') {
      throw new UnauthorizedException('Invalid verification token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });
    if (!user || user.deletedAt || payload.email !== user.email) {
      throw new UnauthorizedException('Invalid verification token');
    }

    if (!user.emailVerifiedAt) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { emailVerifiedAt: new Date() },
      });
    }

    return { message: 'Email verified successfully' };
  }

  private async generateTokens(user: {
    id: string;
    email: string;
    role: Role;
  }) {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
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

    return { accessToken, refreshToken };
  }

  private async buildVerificationUrl(user: { id: string; email: string }) {
    const appUrl = this.configService.get<string>(
      'appUrl',
      'http://localhost:3000',
    );
    const token = await this.jwtService.signAsync(
      { sub: user.id, email: user.email, type: 'email-verification' },
      {
        secret: this.configService.get<string>('jwt.accessSecret'),
        expiresIn: EMAIL_VERIFICATION_TTL as ExpiresIn,
      },
    );
    return `${appUrl}/auth/verify-email?token=${token}`;
  }

  /**
   * Refresh tokens are JWTs longer than bcrypt's 72-byte input limit, which
   * bcrypt silently truncates. Hashing the SHA-256 digest first keeps the full
   * token entropy while still using bcrypt for the stored credential.
   */
  private tokenDigest(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private async hashRefreshToken(token: string): Promise<string> {
    return bcrypt.hash(this.tokenDigest(token), BCRYPT_SALT_ROUNDS);
  }

  private async compareRefreshToken(
    token: string,
    hashed: string,
  ): Promise<boolean> {
    return bcrypt.compare(this.tokenDigest(token), hashed);
  }

  private async storeRefreshToken(userId: string, refreshToken: string) {
    const hashed = await this.hashRefreshToken(refreshToken);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashed },
    });
  }

  private sanitizeUser(user: User) {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      avatar: user.avatar,
      isActive: user.isActive,
      emailVerifiedAt: user.emailVerifiedAt,
    };
  }
}
