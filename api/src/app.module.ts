import { Module, UnauthorizedException } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { DatabaseModule } from "./database/database.module";
import { TaskModule } from "./modules/task/task.module";
import { ListModule } from "./modules/list/list.module";
import configuration from "./config/configuration";
import { UserModule } from './modules/user/user.module';
import { AuthModule } from './modules/auth/auth.module';
import { EmailModule } from './modules/email/email.module';
import { BoardModule } from './modules/board/board.module';
import { BoardUserModule } from './modules/board-user/board-user.module';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from "@nestjs/apollo";
import { join } from "path";
import { RedisModule } from "./redis/redis.module";
import { JwtModule, JwtService } from "@nestjs/jwt";

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
            envFilePath: `.env${process.env.NODE_ENV ? `.${process.env.NODE_ENV}` : ''}`,
            load: [configuration],
        }),
        GraphQLModule.forRootAsync<ApolloDriverConfig>({
            driver: ApolloDriver,
            imports: [ConfigModule, JwtModule],
            inject: [ConfigService, JwtService],
            useFactory: async (configService: ConfigService, jwtService: JwtService) => ({
                autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
                subscriptions: {
                    'graphql-ws': {
                        onConnect: async (context: any) => {
                            const { connectionParams, extra } = context;

                            const authHeader = connectionParams?.Authorization || connectionParams?.authorization;
                            if (!authHeader) {
                                throw new UnauthorizedException();
                            }

                            const [type, token] = authHeader.split(' ');
                            if (type !== 'Bearer' || !token) {
                                throw new UnauthorizedException();
                            }

                            try {
                                const payload = await jwtService.verifyAsync(token, {
                                    secret: configService.get<string>('secret'),
                                });

                                extra.user = {
                                    id: payload.sub,
                                    email: payload.email,
                                };
                            } catch (err) {
                                throw new UnauthorizedException();
                            }
                        },
                    }
                },
                context: ({ req, extra }) => {
                    if (extra && extra.user) {
                        return { user: extra.user };
                    }
                    return { req };
                },
            }),
        }),
        DatabaseModule,
        RedisModule,
        TaskModule,
        ListModule,
        UserModule,
        AuthModule,
        EmailModule,
        BoardModule,
        BoardUserModule,
    ],
})
export class AppModule {}