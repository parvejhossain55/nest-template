import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  app.use(helmet());
  app.use(cookieParser(configService.get<string>('cookie.secret')));
  app.use(compression());

  const env = configService.get<string>('env', 'development');
  const corsOrigin = configService.get<string>('cors.origin', '*');

  // `origin: true` reflects the request origin, which is required instead of
  // `*` when credentials (cookies) are involved. Reflecting every origin with
  // credentials enabled is a security hole, so refuse to boot that way in
  // production — CORS_ORIGIN must be an explicit comma-separated allowlist.
  if (env === 'production' && corsOrigin === '*') {
    throw new Error(
      'Refusing to start in production: CORS_ORIGIN is "*", which would reflect ' +
        'any origin while credentials (cookies) are enabled. Set CORS_ORIGIN to ' +
        'an explicit comma-separated allowlist (e.g. https://app.example.com).',
    );
  }

  app.enableCors({
    origin:
      corsOrigin === '*'
        ? true
        : corsOrigin.split(',').map((entry) => entry.trim()),
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  app.enableShutdownHooks();

  const port = configService.get<number>('port', 3000);
  await app.listen(port);

  Logger.log(
    `🚀 Application running on: http://localhost:${port}`,
    'Bootstrap',
  );
}

void bootstrap();
