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

  // Security headers
  app.use(helmet());

  // Cookie parser
  app.use(cookieParser(configService.get<string>('cookie.secret')));

  // Response compression
  app.use(compression());

  const corsOrigin = configService.get<string>('cors.origin', '*');

  app.enableCors({
    // `origin: true` reflects the request origin, which the browser requires
    // instead of `*` when credentials (cookies) are involved. In production,
    // set CORS_ORIGIN to an explicit comma-separated allowlist.
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

  // Set API prefix + versioning
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // Graceful shutdown
  app.enableShutdownHooks();

  const port = configService.get<number>('port', 3000);
  await app.listen(port);

  Logger.log(
    `🚀 Application running on: http://localhost:${port}`,
    'Bootstrap',
  );
}

bootstrap();
