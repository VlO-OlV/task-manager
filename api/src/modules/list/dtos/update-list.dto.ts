import { InputType, PartialType, PickType } from "@nestjs/graphql";
import { CreateListDto } from "./create-list.dto";

@InputType()
export class UpdateListDto extends PartialType(PickType(CreateListDto, ['name'])) {}