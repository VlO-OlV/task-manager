import { UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserByIdPipe } from '../user/user-by-id.pipe';
import { LocalGuard } from '../../security/local/local.guard';
import { JwtGuard } from '../../security/jwt/jwt.guard';
import { LoginDto, LoginPayload } from './dtos';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { CreateUserDto, User } from '../user/dtos';

@Resolver(() => User)
export class AuthResolver {
  constructor (
    private authService: AuthService,
  ) {}

  @Query(() => User, {
    name: 'me',
  })
  @UseGuards(JwtGuard)
  // @Get('/me')
  async getMe (
    @Context() ctx: any,
  ) {
    return this.authService.getMe(ctx.req.user.id);
  }

  // @Post('/login')
  @Mutation(() => LoginPayload)
  @UseGuards(LocalGuard)
  async login (
    @Args('data') data: LoginDto,
    @Context() ctx: any,
  ) {
    return this.authService.login(ctx.req.user);
  }

  // @Post('/register')
  @Mutation(() => Boolean, { nullable: true })
  async register (
    @Args('data') data: CreateUserDto,
  ) {
    return this.authService.register(data);
  }

  // @Post('/verifyEmail/:userId')
  @Mutation(() => User)
  async verifyEmail (
    @Args('userId', UserByIdPipe) userId: string,
  ) {
    return this.authService.verifyEmail(userId);
  }
}