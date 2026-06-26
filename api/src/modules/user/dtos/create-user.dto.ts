import { Field, InputType } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

@InputType()
export class CreateUserDto {
  @Field()
  @IsString({message: 'First name must be a string'})
  @IsNotEmpty({message: 'First name cannot be empty'})
    firstName: string;

  @Field()
  @IsString({message: 'Last name must be a string'})
  @IsNotEmpty({message: 'Last name cannot be empty'})
    lastName: string;

  @Field()
  @IsEmail({}, {message: 'Incorrect email'})
  @IsNotEmpty({message: 'Email cannot be empty'})
    email: string;

  @Field()
  @IsString({message: 'Password must be a string'})
  @MinLength(8, {message: 'Too short password'})
    password: string;
}