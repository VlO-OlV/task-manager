import { Injectable } from "@nestjs/common";
import { ListRepository } from "../../database/repositories/list.repository";
import { ListIsNotEmptyException } from "../../utils/exceptions/list-is-not-empty.exception";
import { TaskService } from "../task/task.service";
import { CreateListDto, UpdateListDto } from "./dtos";
import { lists } from "../../database/schema";
import { eq } from "drizzle-orm";

@Injectable()
export class ListService {
    constructor (
        private listRepository: ListRepository,
        private taskService: TaskService,
    ) {}

    async create (
        data: CreateListDto,
    ) {
        return this.listRepository.create(data);
    }

    async updateById (
        id: string,
        data: UpdateListDto,
    ) {
        return this.listRepository.updateOne(eq(lists.id, id), data);
    }

    async deleteById (
        id: string,
    ) {
        const listTasks = await this.taskService.getAllByListId(id);
        if (listTasks.length !== 0) {
            throw new ListIsNotEmptyException();
        }
        return this.listRepository.deleteOne(eq(lists.id, id));
    }

    async getById (
        id: string,
    ) {
        return this.listRepository.findOne(eq(lists.id, id));
    }

    async getAll () {
        return this.listRepository.findMany();
    }

    async getAllByBoardId(boardId: string) {
        return this.listRepository.findMany(eq(lists.boardId, boardId));
    }
}