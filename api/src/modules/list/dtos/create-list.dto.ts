import { Field, InputType } from "@nestjs/graphql";
import { IsNotEmpty, IsUUID, MaxLength, MinLength } from "class-validator";

@InputType()
export class CreateListDto {
  @Field()
  @MinLength(3, {message: 'The name is too short. It must have at least 3 characters'})
  @MaxLength(20, {message: 'The name is too long. It must have not more than 20 characters'})
  @IsNotEmpty({message: 'List name cannot be empty'})
    name: string;

  @Field()
  @IsUUID(undefined, {message: 'Board id should be UUID'})
  @IsNotEmpty({message: 'Board id cannot be empty'})
    boardId: string;
}