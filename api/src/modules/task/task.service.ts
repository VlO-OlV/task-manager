import { Injectable } from "@nestjs/common";
import { CreateTaskDto, UpdateTaskDto } from "./dtos";
import { TaskRepository } from "../../database/repositories";
import { tasks } from "../../database/schema";
import { eq } from "drizzle-orm";

@Injectable()
export class TaskService {

    constructor (
        private taskRepository: TaskRepository,
    ) {}

    async create (
        data: CreateTaskDto,
    ) {
        return this.taskRepository.create(data);
    }

    async deleteById (
        id: string,
    ) {
        return this.taskRepository.deleteOne(eq(tasks.id, id));
    }

    async updateById (
        id: string,
        data: UpdateTaskDto,
    ) {
        return this.taskRepository.updateOne(eq(tasks.id, id), data);
    }

    async getById (
        id: string,
    ) {
        return this.taskRepository.findOne(eq(tasks.id, id));
    }

    async getAllByListId (
        listId: string,
    ) {
        return this.taskRepository.findMany(eq(tasks.listId, listId));
    }

    async getAll () {
        return this.taskRepository.findMany();
    }
}