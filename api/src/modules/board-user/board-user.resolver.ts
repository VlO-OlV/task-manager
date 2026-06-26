import { UseGuards } from '@nestjs/common';
import { BoardUserService } from './board-user.service';
import { BoardUserByIdPipe } from './board-user-by-id.pipe';
import { BoardRoles } from '../../utils/decorators/board-roles.decorator';
import { BoardRolesGuard } from '../../security/board-roles/board-roles.guard';
import { JwtGuard } from '../../security/jwt/jwt.guard';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { BoardUser, CreateBoardUserDto, UpdateBoardUserDto } from './dtos';
import { BoardRole } from '../../database/types';

@Resolver(() => BoardUser)
export class BoardUserResolver {
  constructor (
    private boardUserService: BoardUserService,
  ) {}

  @Query(() => [BoardUser], {
    name: 'myBoardUsers',
  })
  @UseGuards(JwtGuard)
  // @Get('/me')
  async getMyBoardUsers (
    @Context() ctx: any,
  ) {
    return this.boardUserService.getAllByUserId(ctx.req.user.id);
  }

  @Mutation(() => BoardUser)
  @BoardRoles(BoardRole.ADMIN)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Post()
  async createBoardUser (
    @Args('data') data: CreateBoardUserDto,
  ) {
    return this.boardUserService.create(data);
  }

  @Mutation(() => BoardUser)
  @BoardRoles(BoardRole.ADMIN)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Patch('/:boardUserId')
  async updateBoardUser (
    @Args('boardUserId', BoardUserByIdPipe) boardUserId: string,
    @Args('data') data: UpdateBoardUserDto,
  ) {
    return this.boardUserService.updateById(boardUserId, data);
  }

  @Mutation(() => BoardUser)
  @BoardRoles(BoardRole.ADMIN)
  @UseGuards(JwtGuard, BoardRolesGuard)
  // @Delete('/:boardUserId')
  async deleteBoardUser (
    @Args('boardUserId', BoardUserByIdPipe) boardUserId: string,
  ) {
    return this.boardUserService.deleteById(boardUserId);
  }
}