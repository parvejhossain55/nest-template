import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { ServiceModule } from './prisma/service/service.module';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [UsersModule, ServiceModule, PrismaModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
