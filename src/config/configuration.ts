export default () => ({
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT ?? '3000', 10),
  appUrl: process.env.APP_URL ?? 'http://localhost:3000',

  database: {
    url: process.env.DATABASE_URL,
  },

  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN ?? '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '7d',
  },

  cookie: {
    secret: process.env.COOKIE_SECRET,
    // Only send the refresh cookie over HTTPS in production.
    secure: process.env.NODE_ENV === 'production',
  },

  cors: {
    origin: process.env.CORS_ORIGIN ?? '*',
  },

  throttle: {
    ttl: parseInt(process.env.THROTTLE_TTL ?? '60', 10),
    limit: parseInt(process.env.THROTTLE_LIMIT ?? '100', 10),
  },

  redis: {
    host: process.env.REDIS_HOST ?? 'localhost',
    port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB ?? '0', 10),
    ttl: parseInt(process.env.REDIS_TTL ?? '3600', 10),
    clusterMode: process.env.REDIS_CLUSTER_MODE === 'true',
    sentinelMode: process.env.REDIS_SENTINEL_MODE === 'true',
  },
});
