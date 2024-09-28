import { Body, Controller, Delete, Get, Param, Patch, Post, UseGuards } from "@nestjs/common";
import { CreateTaskDTO } from "../dtos/CreateTaskDTO";
import { TaskService } from "../services/TaskService";
import { UpdateTaskDTO } from "../dtos/UpdateTaskDTO";
import { TaskByIdPipe } from "../pipes/TaskByIdPipe";
import { JwtGuard } from 'src/security/JwtGuard';

@Controller('/tasks')
export class TaskController {

    constructor (
        private taskService: TaskService,
    ) {}

    @UseGuards(JwtGuard)
    @Post()
    async createTask (
        @Body() body: CreateTaskDTO,
    ) {
        const createdTask = await this.taskService.create(body);
        return createdTask;
    }

    @UseGuards(JwtGuard)
    @Delete('/:id')
    async deleteTaskById (
        @Param('id', TaskByIdPipe) id: string,
    ) {
        const deletedTask = await this.taskService.deleteById(id);
        return deletedTask;
    }
    
    @UseGuards(JwtGuard)
    @Patch('/:id')
    async updateTaskById (
        @Param('id', TaskByIdPipe) id: string,
        @Body() body: UpdateTaskDTO,
    ) {
        const updatedTask = await this.taskService.updateById(id, body);
        return updatedTask;
    }

    @UseGuards(JwtGuard)
    @Get('/:id')
    async getTaskById (
        @Param('id', TaskByIdPipe) id: string,
    ) {
        const task = await this.taskService.getById(id);
        return task;
    }

    @UseGuards(JwtGuard)
    @Get()
    async getAllTasks () {
        const tasks = await this.taskService.getAll();
        return tasks;
    }
}