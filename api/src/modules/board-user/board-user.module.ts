import { Module } from '@nestjs/common';
import { BoardUserService } from './board-user.service';
import { BoardUserResolver } from './board-user.resolver';

@Module({
  providers: [BoardUserResolver, BoardUserService],
  exports: [BoardUserService],
})
export class BoardUserModule {}