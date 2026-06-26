import { Injectable } from '@nestjs/common';
import { UserRepository } from '../../database/repositories/user.repository';
import { eq } from 'drizzle-orm';
import { users } from '../../database/schema';
import { CreateUserDto, UpdateUserDto } from './dtos';

@Injectable()
export class UserService {
  
  constructor (
    private userRepository: UserRepository,
  ) {}

  public async findByEmail(email: string) {
    return this.userRepository.findOne(eq(users.email, email));
  }

  public async findById(id: string) {
    return this.userRepository.findOne(eq(users.id, id));
  }

  public async create(data: CreateUserDto) {
    return this.userRepository.create(data);
  }

  public async updateById(
    id: string,
    data: UpdateUserDto,
  ) {
    return this.userRepository.updateOne(eq(users.id, id), data);
  }

  public async deleteManyByEmail(email: string) {
    return this.userRepository.deleteMany(eq(users.email, email));
  }
}