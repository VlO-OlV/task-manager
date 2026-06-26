import { Field, ObjectType } from "@nestjs/graphql";
import { AbstractEntity } from "../../../utils/graphql/abstract-entity.dto";
import { BoardUser } from "../../board-user/dtos";
import { Priority } from "../../../database/types";

@ObjectType()
export class Task extends AbstractEntity {
  @Field()
  name: string;

  @Field({ nullable: true })
  description?: string;

  @Field(type => Date, { nullable: true })
  deadline?: Date;

  @Field()
  listId: string;

  @Field(type => Priority)
  priority: Priority;

  @Field(type => BoardUser, { nullable: true })
  assignee?: BoardUser;

  @Field({ nullable: true })
  assigneeId?: string;
}