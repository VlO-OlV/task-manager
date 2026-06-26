import { Inject, Injectable } from '@nestjs/common';
import { AbstractRepository } from './abstract.repository';
import * as schema from '../schema';
import { DATABASE_CLIENT } from '../database.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';

@Injectable()
export class BoardUserRepository extends AbstractRepository<
  typeof schema.boardUsers, 
  'boardUsers'
> {
  constructor(
    @Inject(DATABASE_CLIENT) client: NodePgDatabase<typeof schema>,
  ) {
    super(client, schema.boardUsers, 'boardUsers');
  }
}
