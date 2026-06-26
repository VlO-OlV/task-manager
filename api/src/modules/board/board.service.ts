import { Injectable } from '@nestjs/common';
import { BoardRepository } from '../../database/repositories/board.repository';
import { CreateBoardDto, UpdateBoardDto } from './dtos';
import { BoardUserService } from '../board-user/board-user.service';
import { eq } from 'drizzle-orm';
import { boards } from '../../database/schema';
import { BoardRole } from '../../database/types';

@Injectable()
export class BoardService {
  constructor (
    private boardRepository: BoardRepository,
    private boardUserService: BoardUserService,
  ) {}

  async getById(id: string){
    return this.boardRepository.findOne(eq(boards.id, id));
  }

  async create(userId: string, data: CreateBoardDto) {
    const newBoard = await this.boardRepository.create(data);
    await this.boardUserService.create({
      userId,
      boardId: newBoard.id,
      userRole: BoardRole.ADMIN,
    });
    return this.getById(newBoard.id);
  }

  async updateById(id: string, data: UpdateBoardDto) {
    return this.boardRepository.updateOne(eq(boards.id, id), data);
  }

  async deleteById(id: string) {
    return this.boardRepository.deleteOne(eq(boards.id, id));
  }
}