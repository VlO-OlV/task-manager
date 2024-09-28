import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { PrismaModule } from "./modules/PrismaModule";
import { TaskModule } from "./modules/TaskModule";
import { ListModule } from "./modules/ListModule";
import Configuration from "./config/Configuration";
import { UserModule } from './modules/UserModule';
import { AuthModule } from './modules/AuthModule';

@Module({
    imports: [
        ConfigModule.forRoot({
            envFilePath: ['.development.env', '.env'],
            load: [Configuration],
        }),
        PrismaModule,
        TaskModule,
        ListModule,
        UserModule,
        AuthModule,
    ],
})
export class AppModule {}