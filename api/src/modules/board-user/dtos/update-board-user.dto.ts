import { InputType, PartialType, PickType } from '@nestjs/graphql';
import { CreateBoardUserDto } from './create-board-user.dto';

@InputType()
export class UpdateBoardUserDto extends PartialType(PickType(CreateBoardUserDto, ['userRole'])) {}