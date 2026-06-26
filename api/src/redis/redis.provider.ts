import { Provider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import Redis, { RedisOptions } from 'ioredis';

export type RedisClient = Redis;

export const REDIS_PUB_SUB = 'REDIS_PUB_SUB';

export const RedisPubSubProvider: Provider = {
  provide: REDIS_PUB_SUB,
  inject: [ConfigService],
  useFactory: async (configService: ConfigService) => {
    const options: RedisOptions = {
      host: configService.getOrThrow<string>('redis.host'),
      port: configService.getOrThrow<number>('redis.port'),
      password: configService.getOrThrow<string>('redis.password'),
      retryStrategy: (times) => Math.min(times * 200, 2000),
      maxRetriesPerRequest: null,
    };

    const publisher = new Redis(options);
    const subscriber = new Redis(options);

    publisher.on('error', (e) => console.error(`Redis PubSub (Publisher) Error: ${e}`));
    subscriber.on('error', (e) => console.error(`Redis PubSub (Subscriber) Error: ${e}`));

    return new RedisPubSub({
      publisher,
      subscriber,
    });
  },
};