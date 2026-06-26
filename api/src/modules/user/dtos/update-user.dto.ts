import { InputType, PartialType } from "@nestjs/graphql";
import { CreateUserDto } from "./create-user.dto";
import { IsBoolean, IsOptional } from "class-validator";

@InputType()
export class UpdateUserDto extends PartialType(CreateUserDto) {
  @IsBoolean({message: 'Verified state must be a boolean'})
  @IsOptional()
    isVerified?: boolean;
}