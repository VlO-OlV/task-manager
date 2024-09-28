import { Body, Controller, Delete, Get, Param, Patch, Post, UseGuards } from "@nestjs/common";
import { ListService } from "../services/ListService";
import { CreateListDTO } from "../dtos/CreateListDTO";
import { UpdateListDTO } from "../dtos/UpdateListDTO";
import { ListByIdPipe } from "../pipes/ListByIdPipe";
import { JwtGuard } from 'src/security/JwtGuard';

@Controller('/lists')
export class ListController {

    constructor (
        private listService: ListService,
    ) {}

    @UseGuards(JwtGuard)
    @Post()
    async createList (
        @Body() body: CreateListDTO,
    ) {
        const createdList = await this.listService.create(body);
        return createdList;
    }

    @UseGuards(JwtGuard)
    @Patch('/:id')
    async updateListById (
        @Param('id', ListByIdPipe) id: string,
        @Body() body: UpdateListDTO,
    ) {
        const updatedList = await this.listService.updateById(id, body);
        return updatedList;
    }

    @UseGuards(JwtGuard)
    @Delete('/:id')
    async deleteListById (
        @Param('id', ListByIdPipe) id: string,
    ) {
        const deletedList = await this.listService.deleteById(id);
        return deletedList;
    }

    @UseGuards(JwtGuard)
    @Get('/:id')
    async getListById (
        @Param('id', ListByIdPipe) id: string,
    ) {
        const list = await this.listService.getById(id);
        return list;
    }

    @Get()
    async getAllLists () {
        const lists = await this.listService.getAll();
        return lists;
    }
}