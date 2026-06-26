import { Field, ObjectType } from "@nestjs/graphql";
import { AbstractEntity } from "../../../utils/graphql/abstract-entity.dto";
import { Task } from "../../task/dtos";

@ObjectType()
export class List extends AbstractEntity {
  @Field()
  name: string;

  @Field()
  boardId: string;

  @Field(type => [Task])
  tasks: Task[];
}