import { Injectable, PipeTransform } from "@nestjs/common";
import { InvalidEntityIdException } from "../../utils/exceptions/invalid-entity-id.exception";
import { TaskService } from "./task.service";

@Injectable()
export class TaskByIdPipe implements PipeTransform {
    constructor (
        private taskService: TaskService,
    ) {}
    
    async transform(taskId: string) {
        const task = await this.taskService.getById(taskId);
        if (!task) {
            throw new InvalidEntityIdException('Task');
        }
        return taskId;
    }
}