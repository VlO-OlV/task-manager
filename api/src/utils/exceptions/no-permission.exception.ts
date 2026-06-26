import { HttpException, HttpStatus } from '@nestjs/common';

export class NoPermissionException extends HttpException {
  constructor () {
    super('You don\'t have permission to perform this action', HttpStatus.BAD_REQUEST);
  }
}