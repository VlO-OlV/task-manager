import { Injectable } from '@nestjs/common';
import { BoardUserRepository } from '../../database/repositories/board-user.repository';
import { CreateBoardUserDto, UpdateBoardUserDto } from './dtos';
import { and, eq } from 'drizzle-orm';
import { boardUsers } from '../../database/schema';

@Injectable()
export class BoardUserService {
  constructor (
    private boardUserRepository: BoardUserRepository,
  ) {}

  async getAllByUserId(userId: string) {
    return this.boardUserRepository.findMany(eq(boardUsers.userId, userId));
  }

  async getByUserAndBoard(userId: string, boardId: string) {
    return this.boardUserRepository.findOne(and(eq(boardUsers.userId, userId), eq(boardUsers.boardId, boardId)));
  }

  async getAllByBoardId(boardId: string) {
    return this.boardUserRepository.findMany(eq(boardUsers.boardId, boardId));
  }

  async getById(id: string) {
    return this.boardUserRepository.findOne(eq(boardUsers.id, id));
  }

  async create(data: CreateBoardUserDto) {
    return this.boardUserRepository.create(data);
  }

  async updateById(id: string, data: UpdateBoardUserDto) {
    return this.boardUserRepository.updateOne(eq(boardUsers.id, id), data);
  }
  
  async deleteById(id: string) {
    return this.boardUserRepository.deleteOne(eq(boardUsers.id, id));
  }
}