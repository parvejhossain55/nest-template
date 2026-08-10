import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from './database/prisma/prisma.module';
import configuration from './config/configuration';
import { validate } from './config/validation';
import { AuthModule } from './modules/auth/auth.module';
import { CacheModule } from './shared/cache/cache.module';
import { MailModule } from './shared/mail/mail.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validate,
    }),
    PrismaModule,
    CacheModule,
    MailModule,
    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
