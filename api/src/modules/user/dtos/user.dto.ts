import { Field, ObjectType } from "@nestjs/graphql";
import { AbstractEntity } from "../../../utils/graphql/abstract-entity.dto";
import { BoardUser } from "../../board-user/dtos";

@ObjectType()
export class User extends AbstractEntity {
  @Field()
  email: string;

  @Field({ nullable: true })
  username?: string;

  @Field()
  firstName: string;

  @Field()
  lastName: string;

  @Field()
  isVerified: boolean;

  @Field(type => [BoardUser])
  boardUsers: BoardUser[];
}