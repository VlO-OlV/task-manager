import { Field, InputType } from '@nestjs/graphql';
import { IsEnum, IsNotEmpty, IsUUID } from 'class-validator';
import { BoardRole } from '../../../database/types';

@InputType()
export class CreateBoardUserDto {
  @Field()
  @IsUUID(undefined, {message: 'User id should be UUID'})
  @IsNotEmpty({message: 'User id cannot be empty'})
    userId: string;

  @Field()
  @IsUUID(undefined, {message: 'Board id should be UUID'})
  @IsNotEmpty({message: 'Board id cannot be empty'})
    boardId: string;

  @Field(type => BoardRole)
  @IsEnum(BoardRole, {message: 'The board role must be a value from enum'})
    userRole: BoardRole;
}