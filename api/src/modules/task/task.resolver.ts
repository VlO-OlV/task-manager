import { Inject, UseGuards } from "@nestjs/common";
import { TaskService } from "./task.service";
import { TaskByIdPipe } from "./task-by-id.pipe";
import { BoardRolesGuard } from "../../security/board-roles/board-roles.guard";
import { BoardRoles } from "../../utils/decorators/board-roles.decorator";
import { JwtGuard } from "../../security/jwt/jwt.guard";
import { Args, Mutation, Parent, Query, ResolveField, Resolver, Subscription } from "@nestjs/graphql";
import { CreateTaskDto, Task, UpdateTaskDto } from "./dtos";
import { BoardUser } from "../board-user/dtos";
import { BoardUserService } from "../board-user/board-user.service";
import { BoardRole } from "../../database/types";
import { RedisPubSub } from "graphql-redis-subscriptions";
import { REDIS_PUB_SUB } from "../../redis/redis.provider";
import { SubscriptionKey } from "../../utils/consts";

@Resolver(() => Task)
export class TaskResolver {
  constructor (
    private taskService: TaskService,
    private boardUserService: BoardUserService,
    @Inject(REDIS_PUB_SUB)
    private readonly redisPubSub: RedisPubSub,
  ) {}

  @Query(() => Task, {
    name: 'task',
  })
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Get('/:taskId')
  async getTaskById (
    @Args('taskId', TaskByIdPipe) id: string,
  ) {
    const task = await this.taskService.getById(id);
    return task;
  }

  @ResolveField('assignee', () => [BoardUser], { nullable: true })
  async getAssignee(
    @Parent() task: Task,
  ) {
    return this.boardUserService.getById(task.assigneeId);
  }

  @Mutation(() => Task)
  @BoardRoles(BoardRole.ADMIN, BoardRole.MODERATOR)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Post()
  async createTask (
    @Args('data') data: CreateTaskDto,
  ) {
    const createdTask = await this.taskService.create(data);
    await this.redisPubSub.publish(SubscriptionKey.TASK_CREATED, { [SubscriptionKey.TASK_CREATED]: createdTask });
    return createdTask;
  }

  @Mutation(() => Task)
  @BoardRoles(BoardRole.ADMIN, BoardRole.MODERATOR)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Delete('/:taskId')
  async deleteTaskById (
    @Args('taskId', TaskByIdPipe) id: string,
  ) {
    const deletedTask = await this.taskService.deleteById(id);
    return deletedTask;
  }
  
  @Mutation(() => Task)
  @BoardRoles(BoardRole.ADMIN, BoardRole.MODERATOR)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Patch('/:taskId')
  async updateTaskById (
    @Args('taskId', TaskByIdPipe) id: string,
    @Args('data') data: UpdateTaskDto,
  ) {
    const updatedTask = await this.taskService.updateById(id, data);
    await this.redisPubSub.publish(SubscriptionKey.TASK_UPDATED, { [SubscriptionKey.TASK_UPDATED]: updatedTask });
    return updatedTask;
  }

  @Subscription(() => Task, {
    name: SubscriptionKey.TASK_CREATED,
    filter: (payload: { [SubscriptionKey.TASK_CREATED]: Task }, variables: Partial<Pick<Task, 'assigneeId' | 'listId'>>) => {
      const { listId, assigneeId } = payload[SubscriptionKey.TASK_CREATED];
      return (!variables.listId && !variables.assigneeId) || variables.assigneeId === assigneeId || variables.listId === listId;
    },
  })
  async subscribeToTaskCreation() {
    return this.redisPubSub.asyncIterableIterator(SubscriptionKey.TASK_CREATED);
  }

  @Subscription(() => Task, {
    name: SubscriptionKey.TASK_UPDATED,
    filter: (payload: { [SubscriptionKey.TASK_UPDATED]: Task }, variables: Partial<Pick<Task, 'assigneeId' | 'listId'>>) => {
      const { listId, assigneeId } = payload[SubscriptionKey.TASK_UPDATED];
      return (!variables.listId && !variables.assigneeId) || variables.assigneeId === assigneeId || variables.listId === listId;
    },
  })
  async subscribeToTaskUpdate() {
    return this.redisPubSub.asyncIterableIterator(SubscriptionKey.TASK_UPDATED);
  }
}