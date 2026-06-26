import { Field, ObjectType } from "@nestjs/graphql";
import { AbstractEntity } from "../../../utils/graphql/abstract-entity.dto";
import { List } from "../../list/dtos";
import { BoardUser } from "../../board-user/dtos";

@ObjectType()
export class Board extends AbstractEntity {
  @Field()
  name: string;

  @Field(type => [List])
  lists: List[];

  @Field(type => [BoardUser])
  boardUsers: BoardUser[];
}