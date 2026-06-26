import { Field, InputType } from "@nestjs/graphql";
import { Type } from "class-transformer";
import { IsEnum, IsNotEmpty, IsOptional, IsUUID, MaxLength, MinLength } from "class-validator";
import { Priority } from "../../../database/types";

@InputType()
export class CreateTaskDto {
  @Field()
  @MinLength(3, {message: 'The name is too short. It must have at least 3 characters'})
  @MaxLength(20, {message: 'The name is too long. It must have not more than 20 characters'})
  @IsNotEmpty({message: 'Task name cannot be empty'})
    name: string;

  @Field({ nullable: true })
  @IsOptional()
    description?: string;

  @Field(type => Date, { nullable: true })
  @Type(() => Date)
  @IsOptional()
    deadline?: Date;

  @Field()
  @IsUUID(undefined, {message: 'List id should be UUID'})
  @IsNotEmpty({message: 'List id cannot be empty'})
    listId: string;

  @Field(type => Priority)
  @IsEnum(Priority, {message: 'The priority must be a value from enum'})
    priority: Priority;

  @Field({ nullable: true })
  @IsUUID(undefined, {message: 'Id of assignee should be UUID'})
  @IsNotEmpty({message: 'Id of assignee cannot be empty'})
  @IsOptional()
    assigneeId?: string;
}