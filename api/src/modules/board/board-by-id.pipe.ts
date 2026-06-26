import { Injectable, PipeTransform } from '@nestjs/common';
import { InvalidEntityIdException } from '../../utils/exceptions/invalid-entity-id.exception';
import { BoardService } from './board.service';

@Injectable()
export class BoardByIdPipe implements PipeTransform {
  constructor (
    private boardService: BoardService,
  ) {}

  async transform(boardId: string) {
    const board = await this.boardService.getById(boardId);
    if (!board) {
      throw new InvalidEntityIdException('Board');
    }
    return boardId;
  }
}