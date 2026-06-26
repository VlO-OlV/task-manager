import { Module } from "@nestjs/common";
import { TaskService } from "./task.service";
import { TaskResolver } from "./task.resolver";
import { BoardUserModule } from "../board-user/board-user.module";

@Module({
    imports: [BoardUserModule],
    providers: [TaskResolver, TaskService],
    exports: [TaskService],
})
export class TaskModule {}