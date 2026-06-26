import { HttpException, HttpStatus } from '@nestjs/common';

export class NotVerifiedException extends HttpException {
  constructor () {
    super('User is not verified', HttpStatus.BAD_REQUEST);
  }
}