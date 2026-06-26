import { Field, InputType } from '@nestjs/graphql';
import { IsNotEmpty, MaxLength, MinLength } from 'class-validator';

@InputType()
export class CreateBoardDto {
  @Field()
  @MinLength(3, {message: 'The name is too short. It must have at least 3 characters'})
  @MaxLength(40, {message: 'The name is too long. It must have not more than 40 characters'})
  @IsNotEmpty({message: 'Board name cannot be empty'})
    name: string;
}