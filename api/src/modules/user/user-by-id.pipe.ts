import { Injectable, PipeTransform } from '@nestjs/common';
import { InvalidEntityIdException } from '../../utils/exceptions/invalid-entity-id.exception';
import { UserService } from './user.service';

@Injectable()
export class UserByIdPipe implements PipeTransform {

  constructor (
    private userService: UserService,
  ) {}

  async transform (userId: string) {
    const user = await this.userService.findById(userId);
    if (!user) {
      throw new InvalidEntityIdException('User');
    }
    return userId;
  }
}