import { InputType, PickType } from "@nestjs/graphql";
import { CreateUserDto } from "../../user/dtos/create-user.dto";

@InputType()
export class LoginDto extends PickType(CreateUserDto, ['email', 'password']) {}