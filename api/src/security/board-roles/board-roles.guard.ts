import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { NoPermissionException } from '../../utils/exceptions';
import { GqlExecutionContext } from '@nestjs/graphql';
import { BoardUserRepository, ListRepository, TaskRepository } from '../../database/repositories';
import { and, eq } from 'drizzle-orm';
import { boardUsers, lists, tasks } from '../../database/schema';

@Injectable()
export class BoardRolesGuard implements CanActivate {
  constructor (
    private reflector: Reflector,
    private boardUserRepository: BoardUserRepository,
    private taskRepository: TaskRepository,
    private listRepository: ListRepository,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    const args = ctx.getArgs();
    const boardRoles = this.reflector.get<string[]>('boardRoles', context.getHandler());
    const taskId = args.taskId;
    const listId = args.listId;
    const boardId = args.boardId;
    
    if (taskId) {
      const task = await this.taskRepository.findOne(eq(tasks.id, taskId));
      const list = await this.listRepository.findOne(eq(lists.id, task.listId));
      return this.checkUserRole(request.user['id'], list.boardId, boardRoles);
    }

    if (listId) {
      const list = await this.listRepository.findOne(eq(lists.id, listId));
      return this.checkUserRole(request.user['id'], list.boardId, boardRoles);
    }

    if (boardId) {
      return this.checkUserRole(request.user['id'], boardId, boardRoles);
    }
    
    return true;
  }

  async checkUserRole (userId, boardId, boardRoles) {
    const boardUser = await this.boardUserRepository.findOne(and(eq(boardUsers.userId, userId), eq(boardUsers.boardId, boardId)));;
    if (!boardUser) {
      throw new NoPermissionException();
    }
    if (!boardRoles || boardRoles.some((boardRole) => boardRole === boardUser.userRole)) {
      return true;
    }
    throw new NoPermissionException();
  }
}