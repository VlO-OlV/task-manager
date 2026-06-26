import { Module } from "@nestjs/common";
import { ListService } from "./list.service";
import { ListResolver } from "./list.resolver";
import { TaskModule } from "../task/task.module";

@Module({
    imports: [TaskModule],
    providers: [ListResolver, ListService],
    exports: [ListService],
})
export class ListModule {}