import { Inject, Injectable } from '@nestjs/common';
import { AbstractRepository } from './abstract.repository';
import * as schema from '../schema';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DATABASE_CLIENT } from '../database.provider';

@Injectable()
export class UserRepository extends AbstractRepository<
  typeof schema.users, 
  'users'
> {
  constructor(
    @Inject(DATABASE_CLIENT) client: NodePgDatabase<typeof schema>,
  ) {
    super(client, schema.users, 'users');
  }
}
