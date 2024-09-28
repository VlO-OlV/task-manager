import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from '../database/repositories/UserRepository';
import { NotRegisteredException } from 'src/utils/exceptions/NotRegisteredException';
import * as bcrypt from 'bcrypt';
import { User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

  constructor (
    private userRepository: UserRepository,
    private jwtService: JwtService,
  ) {}

  private async checkPassword (password: string, hashedPassword: string) {
    return bcrypt.compare(password, hashedPassword);
  }

  async validateUser (email: string, password: string) {
    const user = await this.userRepository.find({ email });
    if (!user) {
      throw new NotRegisteredException('email');
    }
    const isCorrectPassword = await this.checkPassword(password, user.password);
    if (!isCorrectPassword) {
      throw new UnauthorizedException('Password is incorrect');
    }
    const { password: userPassWord, ...result } = user;
    return result;
  }
  
  async login(user: User) {
    const payload = { email: user.email, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}