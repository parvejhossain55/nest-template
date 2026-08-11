import { ConfigService } from '@nestjs/config';
import { CookieOptions } from 'express';

export const REFRESH_TOKEN_COOKIE = 'refresh_token';

/** Attributes shared by both setting and clearing the refresh cookie. */
function baseCookieOptions(configService: ConfigService): CookieOptions {
  return {
    httpOnly: true,
    secure: configService.get<boolean>('cookie.secure', false),
    sameSite: 'lax',
    path: '/auth',
  };
}

/**
 * Options for setting the refresh-token cookie. The cookie lives for exactly
 * as long as the refresh JWT itself so the two can never drift apart.
 */
export function refreshCookieOptions(
  configService: ConfigService,
  expiresAt: Date,
): CookieOptions {
  return {
    ...baseCookieOptions(configService),
    maxAge: Math.max(expiresAt.getTime() - Date.now(), 0),
  };
}

/** Options that match how the cookie was set, used to clear it on logout. */
export function clearRefreshCookieOptions(
  configService: ConfigService,
): CookieOptions {
  return baseCookieOptions(configService);
}
