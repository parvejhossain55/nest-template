import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { Throttle } from '@nestjs/throttler';
import { Public } from '../../core/decorators/public.decorator';
import { CurrentUser } from '../../core/decorators/current-user.decorator';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import {
  ResendVerificationDto,
  VerifyEmailDto,
} from './dto/extra-auth.dto';
import { AuthService } from './auth.service';
import {
  REFRESH_TOKEN_COOKIE,
  clearRefreshCookieOptions,
  refreshCookieOptions,
} from './helper/cookie.helper';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  // Credential endpoints get a tighter budget than the global default.
  private static readonly AUTH_THROTTLE = {
    default: { limit: 20, ttl: 60_000 },
  } as const;

  @Throttle(AuthController.AUTH_THROTTLE)
  @Public()
  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { user, accessToken, refreshToken, expiresAt } =
      await this.authService.register(dto);

    res.cookie(
      REFRESH_TOKEN_COOKIE,
      refreshToken,
      refreshCookieOptions(this.configService, expiresAt),
    );

    return { user, accessToken };
  }

  @Throttle(AuthController.AUTH_THROTTLE)
  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { user, accessToken, refreshToken, expiresAt } =
      await this.authService.login(dto);

    res.cookie(
      REFRESH_TOKEN_COOKIE,
      refreshToken,
      refreshCookieOptions(this.configService, expiresAt),
    );

    return { user, accessToken };
  }

  // Public on purpose: logout must work even when the access token has
  // expired, so a user can always clear their session cookie.
  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = (req.cookies as Record<string, string> |
      undefined)?.[REFRESH_TOKEN_COOKIE];
    if (refreshToken) {
      await this.authService.logout(refreshToken);
    }

    // Idempotent: clearing a cookie that is already gone is still a success.
    res.clearCookie(
      REFRESH_TOKEN_COOKIE,
      clearRefreshCookieOptions(this.configService),
    );

    return { message: 'Logged out successfully' };
  }

  @Get('me')
  me(@CurrentUser() user: { id: string }) {
    return this.authService.getMe(user.id);
  }

  @Throttle(AuthController.AUTH_THROTTLE)
  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = this.extractRefreshToken(req);

    try {
      const {
        accessToken,
        refreshToken: newRefreshToken,
        expiresAt,
      } = await this.authService.refresh(refreshToken);

      res.cookie(
        REFRESH_TOKEN_COOKIE,
        newRefreshToken,
        refreshCookieOptions(this.configService, expiresAt),
      );

      return { accessToken };
    } catch (error) {
      // A failed rotation leaves a dead cookie behind — clear it so the client
      // doesn't keep retrying an invalid session.
      res.clearCookie(
        REFRESH_TOKEN_COOKIE,
        clearRefreshCookieOptions(this.configService),
      );
      throw error;
    }
  }

  // POST, not GET: the verification token is a credential and must not be
  // exposed in URLs (logs, history, Referer headers).
  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('verify-email')
  verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto.token);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('resend-verification')
  resendVerification(@Body() dto: ResendVerificationDto) {
    return this.authService.resendVerification(dto.email);
  }

  /**
   * The refresh token is only ever read from the httpOnly cookie. Accepting it
   * from the request body or the URL would let page JavaScript exfiltrate it
   * (XSS), defeating the cookie's whole purpose.
   */
  private extractRefreshToken(req: Request): string {
    const refreshToken = (req.cookies as Record<string, string> |
      undefined)?.[REFRESH_TOKEN_COOKIE];
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }
    return refreshToken;
  }
}
