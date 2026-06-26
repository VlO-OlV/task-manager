import { Field, ObjectType } from "@nestjs/graphql";
import { AbstractEntity } from "../../../utils/graphql/abstract-entity.dto";
import { BoardRole } from "../../../database/types";

@ObjectType()
export class BoardUser extends AbstractEntity {
  @Field()
  userId: string;

  @Field()
  boardId: string;

  @Field(type => BoardRole)
  userRole: BoardRole;
}