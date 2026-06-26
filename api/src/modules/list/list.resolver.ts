import { UseGuards } from "@nestjs/common";
import { ListService } from "./list.service";
import { ListByIdPipe } from "./list-by-id.pipe";
import { BoardRoles } from "../../utils/decorators/board-roles.decorator";
import { BoardRolesGuard } from "../../security/board-roles/board-roles.guard";
import { JwtGuard } from "../../security/jwt/jwt.guard";
import { Args, Mutation, Parent, Query, ResolveField, Resolver } from "@nestjs/graphql";
import { CreateListDto, List, UpdateListDto } from "./dtos";
import { Task } from "../task/dtos";
import { TaskService } from "../task/task.service";
import { BoardRole } from "../../database/types";

@Resolver(() => List)
export class ListResolver {
  constructor (
    private listService: ListService,
    private taskService: TaskService,
  ) {}

  @Query(() => List, {
    name: 'list',
  })
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Get('/:listId')
  async getListById (
    @Args('listId', ListByIdPipe) id: string,
  ) {
    const list = await this.listService.getById(id);
    return list;
  }

  @Query(() => [List], {
    name: 'lists',
  })
  @UseGuards(JwtGuard)
  // @Get()
  async getAllLists () {
    const lists = await this.listService.getAll();
    return lists;
  }

  @ResolveField('tasks', () => [Task])
  async getTasks(
    @Parent() list: List,
  ) {
    return this.taskService.getAllByListId(list.id);
  }

  @Mutation(() => List)
  @BoardRoles(BoardRole.ADMIN, BoardRole.MODERATOR)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Post()
  async createList (
    @Args('data') data: CreateListDto,
  ) {
    const createdList = await this.listService.create(data);
    return createdList;
  }

  @Mutation(() => List)
  @BoardRoles(BoardRole.ADMIN, BoardRole.MODERATOR)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Patch('/:listId')
  async updateListById (
    @Args('listId', ListByIdPipe) id: string,
    @Args('data') data: UpdateListDto,
  ) {
    const updatedList = await this.listService.updateById(id, data);
    return updatedList;
  }

  @Mutation(() => List)
  @BoardRoles(BoardRole.ADMIN, BoardRole.MODERATOR)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Delete('/:listId')
  async deleteListById (
    @Args('listId', ListByIdPipe) id: string,
  ) {
    const deletedList = await this.listService.deleteById(id);
    return deletedList;
  }
}