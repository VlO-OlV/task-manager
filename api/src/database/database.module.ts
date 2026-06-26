import { Global, Module } from "@nestjs/common";
import { TaskRepository } from "./repositories/task.repository";
import { ListRepository } from "./repositories/list.repository";
import { UserRepository } from "./repositories/user.repository";
import { BoardRepository } from "./repositories/board.repository";
import { BoardUserRepository } from "./repositories/board-user.repository";
import { DATABASE_CLIENT, DatabaseProvider } from "./database.provider";
import { ConfigModule } from "@nestjs/config";

@Global()
@Module({
  imports: [ConfigModule],
  providers: [
    DatabaseProvider,
    TaskRepository,
    ListRepository,
    UserRepository,
    BoardRepository,
    BoardUserRepository,
  ],
  exports: [
    DATABASE_CLIENT,
    TaskRepository,
    ListRepository,
    UserRepository,
    BoardRepository,
    BoardUserRepository,
  ],
})
export class DatabaseModule {}