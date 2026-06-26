import { HttpException, HttpStatus } from '@nestjs/common';

export class AlreadyRegisteredException extends HttpException {
  constructor () {
    super('This user is already registered', HttpStatus.BAD_REQUEST);
  }
}