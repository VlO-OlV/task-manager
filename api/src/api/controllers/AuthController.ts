import { Controller, Post, Request, UseGuards } from '@nestjs/common';
import { AuthService } from '../services/AuthService';
import { LocalGuard } from 'src/security/LocalGuard';

@Controller('/auth')
export class AuthController {

  constructor (
    private authService: AuthService,
  ) {}

  @Post('/login')
  @UseGuards(LocalGuard)
  async login (
    @Request() req,
  ) {
    return this.authService.login(req.user);
  }
}