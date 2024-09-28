import { Injectable } from '@nestjs/common';
import { UserRepository } from '../database/repositories/UserRepository';

@Injectable()
export class UserService {
  
  constructor (
    private userRepoitory: UserRepository,
  ) {}

}