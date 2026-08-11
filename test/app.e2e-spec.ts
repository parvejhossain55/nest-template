import {
  INestApplication,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { App } from 'supertest/types';
import request from 'supertest';
import cookieParser from 'cookie-parser';
import { AppModule } from './../src/app.module';
import { PrismaService } from '../src/database/prisma/prisma.service';
import { MailService } from '../src/shared/mail/mail.service';

const API = '/api/v1/auth';

describe('Auth (e2e)', () => {
  let app: INestApplication<App>;
  let prisma: PrismaService;

  const email = `e2e-${Date.now()}@example.com`;
  const password = 'password123';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      // No SMTP in tests — assert on DB state instead.
      .overrideProvider(MailService)
      .useValue({ sendWelcomeEmail: jest.fn().mockResolvedValue(undefined) })
      .compile();

    app = moduleFixture.createNestApplication();
    // Mirror src/main.ts so tests exercise the real routing + middleware.
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
        forbidNonWhitelisted: true,
        transformOptions: { enableImplicitConversion: true },
      }),
    );
    app.setGlobalPrefix('api');
    app.enableVersioning({ type: VersioningType.URI, defaultVersion: '1' });
    await app.init();

    prisma = app.get(PrismaService);
  });

  afterAll(async () => {
    await prisma.user.deleteMany({ where: { email: { startsWith: 'e2e-' } } });
    await app.close();
  });

  /** Returns the full `refresh_token=...` cookie from a response. */
  const refreshCookie = (res: request.Response): string => {
    const setCookie = res.headers['set-cookie'];
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    const cookie = cookies.find((c) => c?.startsWith('refresh_token='));
    if (!cookie) throw new Error('refresh_token cookie was not set');
    return cookie.split(';')[0];
  };

  const register = () =>
    request(app.getHttpServer())
      .post(`${API}/register`)
      .send({ email, password, name: 'E2E User' });

  const login = (overrides: Record<string, unknown> = {}) =>
    request(app.getHttpServer())
      .post(`${API}/login`)
      .send({ email, password, ...overrides });

  it('POST /register creates a user, returns an access token, sets refresh cookie', async () => {
    const res = await register().expect(201);

    expect(res.body.user.email).toBe(email);
    expect(res.body.user.password).toBeUndefined();
    expect(res.body.accessToken).toBeDefined();
    // The refresh token lives only in the httpOnly cookie, never in the body.
    expect(res.body.refreshToken).toBeUndefined();
    expect(refreshCookie(res)).toBeDefined();
  });

  it('POST /register rejects duplicate emails with 409', async () => {
    await register().expect(409);
  });

  it('GET /me rejects requests without a token', async () => {
    await request(app.getHttpServer()).get(`${API}/me`).expect(401);
  });

  it('POST /login + GET /me round-trip', async () => {
    const res = await login().expect(200);

    const me = await request(app.getHttpServer())
      .get(`${API}/me`)
      .set('Authorization', `Bearer ${res.body.accessToken}`)
      .expect(200);

    expect(me.body.email).toBe(email);
  });

  it('POST /login rejects bad credentials with 401', async () => {
    await login({ password: 'wrong-password' }).expect(401);
  });

  it('POST /refresh rotates the refresh cookie; rotated-away tokens are single-use', async () => {
    const first = await login().expect(200);
    const firstCookie = refreshCookie(first);

    const rotated = await request(app.getHttpServer())
      .post(`${API}/refresh`)
      .set('Cookie', firstCookie)
      .expect(200);

    expect(rotated.body.accessToken).toBeDefined();
    expect(rotated.body.refreshToken).toBeUndefined();
    expect(refreshCookie(rotated)).not.toBe(firstCookie);

    // Reusing the rotated-away token is rejected (and revokes the family).
    await request(app.getHttpServer())
      .post(`${API}/refresh`)
      .set('Cookie', firstCookie)
      .expect(401);
  });

  it('concurrent refresh with the same token issues exactly one new pair', async () => {
    const res = await login().expect(200);
    const cookie = refreshCookie(res);

    const responses = await Promise.all([
      request(app.getHttpServer()).post(`${API}/refresh`).set('Cookie', cookie),
      request(app.getHttpServer()).post(`${API}/refresh`).set('Cookie', cookie),
    ]);

    const statuses = responses.map((r) => r.status).sort((a, b) => a - b);
    expect(statuses).toEqual([200, 401]);
  });

  it('POST /logout revokes the session even without a valid access token', async () => {
    const res = await login().expect(200);
    const cookie = refreshCookie(res);

    // No Authorization header at all — logout must not need an unexpired token.
    await request(app.getHttpServer())
      .post(`${API}/logout`)
      .set('Cookie', cookie)
      .expect(200);

    // The revoked session can no longer be used to refresh.
    await request(app.getHttpServer())
      .post(`${API}/refresh`)
      .set('Cookie', cookie)
      .expect(401);

    // Logout without a cookie is idempotent.
    await request(app.getHttpServer()).post(`${API}/logout`).expect(200);
  });

  it('POST /verify-email rejects invalid tokens', async () => {
    await request(app.getHttpServer())
      .post(`${API}/verify-email`)
      .send({ token: 'not-a-real-token' })
      .expect(401);
  });

  it('POST /resend-verification never reveals whether an email exists', async () => {
    const registered = await request(app.getHttpServer())
      .post(`${API}/resend-verification`)
      .send({ email })
      .expect(200);
    expect(registered.body.message).toBeDefined();

    const unknown = await request(app.getHttpServer())
      .post(`${API}/resend-verification`)
      .send({ email: 'nobody@example.com' })
      .expect(200);
    expect(unknown.body.message).toBe(registered.body.message);
  });
});
