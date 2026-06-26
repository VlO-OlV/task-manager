import { HttpException, HttpStatus } from '@nestjs/common';

export class ListIsNotEmptyException extends HttpException {
  constructor () {
    super('List is not empty', HttpStatus.BAD_REQUEST);
  }
}