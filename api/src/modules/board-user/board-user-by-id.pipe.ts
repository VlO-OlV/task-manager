import { Injectable, PipeTransform } from '@nestjs/common';
import { InvalidEntityIdException } from '../../utils/exceptions/invalid-entity-id.exception';
import { BoardUserService } from './board-user.service';

@Injectable()
export class BoardUserByIdPipe implements PipeTransform {
  constructor (
    private boardUserService: BoardUserService,
  ) {}

  async transform(boardUserId: string) {
    const board = await this.boardUserService.getById(boardUserId);
    if (!board) {
      throw new InvalidEntityIdException('Board user');
    }
    return boardUserId;
  }
}