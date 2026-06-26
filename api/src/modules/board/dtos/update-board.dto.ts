import { InputType, PartialType } from '@nestjs/graphql';
import { CreateBoardDto } from './create-board.dto';

@InputType()
export class UpdateBoardDto extends PartialType(CreateBoardDto) {}