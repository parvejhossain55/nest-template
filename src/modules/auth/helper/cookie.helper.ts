import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { CookieOptions } from 'express';

export const REFRESH_TOKEN_COOKIE = 'refresh_token';

/** Attributes shared by both setting and clearing the refresh cookie. */
function baseCookieOptions(configService: ConfigService): CookieOptions {
  return {
    httpOnly: true,
    secure: configService.get<boolean>('cookie.secure', false),
    sameSite: 'lax',
    path: '/',
  };
}

/**
 * Options for setting the refresh-token cookie. The cookie lives for exactly
 * as long as the refresh JWT itself so the two can never drift apart.
 */
function refreshCookieOptions(
  configService: ConfigService,
  expiresAt: Date,
): CookieOptions {
  return {
    ...baseCookieOptions(configService),
    maxAge: Math.max(expiresAt.getTime() - Date.now(), 0),
  };
}

/** Options that match how the cookie was set, used to clear it on logout. */
function clearRefreshCookieOptions(
  configService: ConfigService,
): CookieOptions {
  return baseCookieOptions(configService);
}

/** Sets the refresh-token cookie to match the just-issued refresh JWT. */
export function setRefreshCookie(
  res: Response,
  configService: ConfigService,
  refreshToken: string,
  expiresAt: Date,
): void {
  res.cookie(
    REFRESH_TOKEN_COOKIE,
    refreshToken,
    refreshCookieOptions(configService, expiresAt),
  );
}

/** Clears the refresh-token cookie (logout or a failed rotation). */
export function clearRefreshCookie(
  res: Response,
  configService: ConfigService,
): void {
  res.clearCookie(
    REFRESH_TOKEN_COOKIE,
    clearRefreshCookieOptions(configService),
  );
}

/** Reads the refresh token from the httpOnly cookie, if present. */
export function getRefreshToken(req: Request): string | undefined {
  return (req.cookies as Record<string, string> | undefined)?.[
    REFRESH_TOKEN_COOKIE
  ];
}
