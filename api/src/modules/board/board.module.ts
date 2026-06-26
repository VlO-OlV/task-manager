import { Module } from '@nestjs/common';
import { BoardService } from './board.service';
import { BoardResolver } from './board.resolver';
import { ListModule } from '../list/list.module';
import { BoardUserModule } from '../board-user/board-user.module';

@Module({
  imports: [ListModule, BoardUserModule],
  providers: [BoardResolver, BoardService],
})
export class BoardModule {}