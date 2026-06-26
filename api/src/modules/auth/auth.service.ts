import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { EmailService } from '../email/email.service';
import { ConfigService } from '@nestjs/config';
import { NotVerifiedException } from '../../utils/exceptions/not-verified.exception';
import { NotRegisteredException } from '../../utils/exceptions/not-registered.exception';
import { AlreadyRegisteredException } from '../../utils/exceptions/already-registered.exception';
import { User } from '../../database/types';
import { UserService } from '../user/user.service';
import { CreateUserDto } from '../user/dtos';

@Injectable()
export class AuthService {

  constructor (
    private userService: UserService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private configService: ConfigService,
  ) {}

  private async checkPassword (password: string, hashedPassword: string) {
    return bcrypt.compare(password, hashedPassword);
  }

  async validateUser (email: string, password: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new NotRegisteredException('email');
    }
    if (!user.isVerified) {
      throw new NotVerifiedException();
    }
    const isCorrectPassword = await this.checkPassword(password, user.password);
    if (!isCorrectPassword) {
      throw new UnauthorizedException('Password is incorrect');
    }
    const { password: userPassWord, ...result } = user;
    return result;
  }
  
  async login (user: User) {
    const payload = { email: user.email, sub: user.id };
    return {
      accessToken: this.jwtService.sign(payload),
    };
  }

  async register(data: CreateUserDto) {
    const user = await this.userService.findByEmail(data.email);
    if (user) {
      throw new AlreadyRegisteredException();
    }
    const newUser = await this.userService.create({
      ...data,
      password: await bcrypt.hash(data.password, await bcrypt.genSalt()),
    });
    await this.requestEmailVerification(data.email);

    new Promise((resolve, reject) => {
      setTimeout(() => {
        this.userService.findByEmail(data.email)
          .then((user) => {
            if (!user.isVerified) {
              resolve(
                this.userService.deleteManyByEmail(user.email)
              );
            }
            resolve(false);
          })
          .catch(reject);
      }, 3600*1000);
    });
  }

  async requestEmailVerification (email: string) {
    const userToVerify = await this.userService.findByEmail(email);

    const url = this.configService.get<string>('frontBaseUrl');
    await this.emailService.sendEmail({
      to: email,
      subject: 'Email verification',
      message: `Click here to verify --> ${url}/verifyEmail/${userToVerify.id}`,
    });
  }

  async verifyEmail (userId: string) {
    const { password, ...verifiedUser } = await this.userService.updateById(userId, {
      isVerified: true,
    });
    return verifiedUser;
  }

  async getMe (userId: string) {
    const { password, ...user } = await this.userService.findById(userId);
    return user;
  }
}