import { UseGuards } from '@nestjs/common';
import { BoardService } from './board.service';
import { BoardByIdPipe } from './board-by-id.pipe';
import { BoardRolesGuard } from '../../security/board-roles/board-roles.guard';
import { BoardRoles } from '../../utils/decorators/board-roles.decorator';
import { JwtGuard } from '../../security/jwt/jwt.guard';
import { Args, Context, Mutation, Parent, Query, ResolveField, Resolver } from '@nestjs/graphql';
import { Board, CreateBoardDto, UpdateBoardDto } from './dtos';
import { List } from '../list/dtos';
import { ListService } from '../list/list.service';
import { BoardUser } from '../board-user/dtos';
import { BoardUserService } from '../board-user/board-user.service';
import { BoardRole } from '../../database/types';

@Resolver(() => Board)
export class BoardResolver {
  constructor (
    private boardService: BoardService,
    private listService: ListService,
    private boardUserService: BoardUserService,
  ) {}

  @Query(() => Board,{
    name: 'board',
  })
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Get('/:boardId')
  async getBoardById (
    @Args('boardId', BoardByIdPipe) boardId: string,
  ) {
    return this.boardService.getById(boardId);
  }

  @ResolveField('lists', () => [List])
  async getLists (
    @Parent() board: Board,
  ) {
    return this.listService.getAllByBoardId(board.id);
  }

  @ResolveField('boardUsers', () => [BoardUser])
  async getUsers (
    @Parent() board: Board,
  ) {
    return this.boardUserService.getAllByBoardId(board.id);
  }

  @Mutation(() => Board)
  @UseGuards(JwtGuard)
  // @Post()
  async createBoard (
    @Context() ctx: any,
    @Args('data') data: CreateBoardDto,
  ) {
    return this.boardService.create(ctx.req.user.id, data);
  }

  @Mutation(() => Board)
  @BoardRoles(BoardRole.ADMIN)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Patch('/:boardId')
  async updateBoardById (
    @Args('data') data: UpdateBoardDto,
    @Args('boardId', BoardByIdPipe) boardId: string,
  ) {
    return this.boardService.updateById(boardId, data);
  }

  @Mutation(() => Board)
  @BoardRoles(BoardRole.ADMIN)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Delete('/:boardId')
  async deleteBoardById (
    @Args('boardId', BoardByIdPipe) boardId: string,
  ) {
    return this.boardService.deleteById(boardId);
  }
}