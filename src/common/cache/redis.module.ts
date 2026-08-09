import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Keyv } from 'keyv';
import KeyvRedis from '@keyv/redis';

@Module({
  imports: [
    ConfigModule,
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: (configService: ConfigService) => {
        const host = configService.get<string>('redis.host');
        const port = configService.get<number>('redis.port');
        const password = configService.get<string>('redis.password');
        const db = configService.get<number>('redis.db');
        const ttl = (configService.get<number>('redis.ttl') ?? 0) * 1000;

        const url = password ? `redis://:${password}@${host}:${port}/${db}` : `redis://${host}:${port}/${db}`;

        return {
          stores: [
            new Keyv({
              store: new KeyvRedis(url),
              ttl,
            }),
          ],
        };
      },
      inject: [ConfigService],
    }),
  ],
  exports: [CacheModule],
})
export class RedisModule {}