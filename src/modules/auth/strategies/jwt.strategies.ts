import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/database/prisma/prisma.service';
import { CacheService } from 'src/shared/cache/cache.service';
import { UserStatus } from '@prisma/client';
import { JwtPayload } from '../types/jwt-payload.types';

/** How long (ms) to cache the validated user before re-checking the DB. */
const USER_CACHE_TTL_MS = 30_000; // 30 seconds

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
    private cacheService: CacheService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow<string>('jwt.accessSecret'),
    });
  }

  async validate(payload: JwtPayload) {
    const cacheKey = this.cacheService.buildKey('jwt:user', payload.sub);

    // Return cached user if available; otherwise hit the DB and cache.
    const cached = await this.cacheService.get<{
      id: string;
      email: string;
      role: string;
      emailVerifiedAt: string | null;
    }>(cacheKey);
    if (cached) {
      this.ensureEmailVerified(cached.emailVerifiedAt);
      return { id: cached.id, email: cached.email, role: cached.role };
    }

    const user = await this.prisma.user.findFirst({
      where: { id: payload.sub, deletedAt: null, status: UserStatus.ACTIVE },
      select: { id: true, email: true, role: true, emailVerifiedAt: true },
    });
    if (!user) throw new UnauthorizedException();

    await this.cacheService.set(cacheKey, user, USER_CACHE_TTL_MS);

    this.ensureEmailVerified(user.emailVerifiedAt);

    return { id: user.id, email: user.email, role: user.role };
  }

  /**
   * Blocks access for users who haven't verified their email. Throws 403
   * (Forbidden) rather than 401 so the client can distinguish "you need to
   * verify your email" from "your token is invalid".
   */
  private ensureEmailVerified(
    emailVerifiedAt: Date | string | null | undefined,
  ): void {
    if (!emailVerifiedAt) {
      throw new UnauthorizedException(
        'Email verification required. Please verify your email before accessing this resource.',
      );
    }
  }

  /**
   * Invalidate the cached user so the next request re-reads from the DB.
   * Call this after role changes, account suspension, or password changes.
   */
  async invalidateUserCache(userId: string): Promise<void> {
    await this.cacheService.del(this.cacheService.buildKey('jwt:user', userId));
  }
}
