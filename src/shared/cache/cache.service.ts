// cache.service.ts
import { Inject, Injectable, Logger } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';

@Injectable()
export class CacheService {
  private readonly logger = new Logger(CacheService.name);

  constructor(@Inject(CACHE_MANAGER) private readonly cacheManager: Cache) {}

  /**
   * Reads a value from cache. Returns undefined on error instead of throwing,
   * so a cache outage never breaks the main flow.
   */
  async get<T = unknown>(key: string): Promise<T | undefined> {
    try {
      return await this.cacheManager.get<T>(key);
    } catch (err) {
      this.logger.warn(`Cache GET failed for key "${key}": ${err.message}`);
      return undefined;
    }
  }

  /**
   * Sets a value in cache. ttl is in milliseconds; if omitted, the module's
   * default ttl is used.
   */
  async set<T = unknown>(key: string, value: T, ttl?: number): Promise<void> {
    try {
      await this.cacheManager.set(key, value, ttl);
    } catch (err) {
      this.logger.warn(`Cache SET failed for key "${key}": ${err.message}`);
    }
  }

  /**
   * Deletes a single key.
   */
  async del(key: string): Promise<void> {
    try {
      await this.cacheManager.del(key);
    } catch (err) {
      this.logger.warn(`Cache DEL failed for key "${key}": ${err.message}`);
    }
  }

  /**
   * Deletes multiple keys at once.
   */
  async delMany(keys: string[]): Promise<void> {
    await Promise.all(keys.map((key) => this.del(key)));
  }

  /**
   * Finds and deletes keys matching a pattern (e.g. "user:*").
   * Requires access to the underlying redis client from KeyvRedis to iterate keys.
   */
  async delByPattern(pattern: string): Promise<void> {
    try {
      const store: any = (this.cacheManager as any).stores?.[0]?.store;
      const redisClient = store?.client ?? store?.redis;

      if (!redisClient) {
        this.logger.warn(
          'delByPattern: could not find underlying redis client',
        );
        return;
      }

      const keys: string[] = [];
      for await (const key of redisClient.scanIterator({ MATCH: pattern })) {
        keys.push(key);
      }

      if (keys.length > 0) {
        await redisClient.del(keys);
      }
    } catch (err) {
      this.logger.warn(
        `Cache delByPattern failed for "${pattern}": ${err.message}`,
      );
    }
  }

  /**
   * Flushes the entire cache.
   */
  async reset(): Promise<void> {
    try {
      await this.cacheManager.clear();
    } catch (err) {
      this.logger.warn(`Cache RESET failed: ${err.message}`);
    }
  }

  /**
   * Cache-aside pattern: returns the cached value if present, otherwise
   * calls fetchFn(), caches the result, and returns it.
   */
  async wrap<T>(
    key: string,
    fetchFn: () => Promise<T>,
    ttl?: number,
  ): Promise<T> {
    try {
      const cached = await this.cacheManager.get<T>(key);
      if (cached !== undefined && cached !== null) {
        return cached;
      }
    } catch (err) {
      this.logger.warn(`Cache wrap GET failed for "${key}": ${err.message}`);
    }

    const result = await fetchFn();

    try {
      await this.cacheManager.set(key, result, ttl);
    } catch (err) {
      this.logger.warn(`Cache wrap SET failed for "${key}": ${err.message}`);
    }

    return result;
  }

  /**
   * Builds a consistent cache key from parts, e.g. buildKey('user', 123) -> "user:123".
   */
  buildKey(...parts: (string | number)[]): string {
    return parts.filter((p) => p !== undefined && p !== null).join(':');
  }
}
