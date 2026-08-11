import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { Public } from '../../core/decorators/public.decorator';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LogoutDto, VerifyEmailDto } from './dto/extra-auth.dto';
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

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(
    @Req() req: Request,
    @Body() dto: LogoutDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = this.extractRefreshToken(req, dto.refreshToken);
    if (refreshToken) {
      await this.authService.logout(refreshToken);
    }

    res.clearCookie(
      REFRESH_TOKEN_COOKIE,
      clearRefreshCookieOptions(this.configService),
    );

    return { message: 'Logged out successfully' };
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Body() dto: RefreshTokenDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = this.extractRefreshToken(req, dto.refreshToken);

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

  @Public()
  @Get('verify-email')
  verifyEmail(@Query() query: VerifyEmailDto) {
    return this.authService.verifyEmail(query.token);
  }

  /**
   * Prefer the httpOnly cookie; fall back to the request body for backwards
   * compatibility with clients that still send the token explicitly.
   */
  private extractRefreshToken(req: Request, bodyToken?: string): string {
    const cookies = req.cookies as Record<string, string> | undefined;
    const refreshToken = cookies?.[REFRESH_TOKEN_COOKIE] ?? bodyToken;
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }
    return refreshToken;
  }
}
