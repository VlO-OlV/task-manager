import { Inject, Injectable } from "@nestjs/common";
import * as schema from '../schema';
import { AbstractRepository } from "./abstract.repository";
import { DATABASE_CLIENT } from "../database.provider";
import { NodePgDatabase } from "drizzle-orm/node-postgres";

@Injectable()
export class TaskRepository extends AbstractRepository<
  typeof schema.tasks, 
  'tasks'
> {
  constructor(
    @Inject(DATABASE_CLIENT) client: NodePgDatabase<typeof schema>,
  ) {
    super(client, schema.tasks, 'tasks');
  }
}
