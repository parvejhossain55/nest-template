import { Logger, ValidationPipe } from '@nestjs/common';
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

  app.enableCors({
    origin: configService.get<string>('cors.origin', '*'),
    credential: true
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  // Graceful shutdown
  app.enableShutdownHooks();

  const port = configService.get<number>('port', 3000);
  await app.listen(port);

  Logger.log(`🚀 Application running on: http://localhost:${port}`, 'Bootstrap');
}

bootstrap();
