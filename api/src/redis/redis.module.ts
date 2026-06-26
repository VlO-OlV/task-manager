import { Global, Module } from "@nestjs/common";
import { REDIS_PUB_SUB, RedisPubSubProvider } from "./redis.provider";

@Global()
@Module({
  providers: [RedisPubSubProvider],
  exports: [REDIS_PUB_SUB],
})
export class RedisModule {}