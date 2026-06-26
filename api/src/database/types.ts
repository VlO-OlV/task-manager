import { InferSelectModel } from 'drizzle-orm';
import * as schema from './schema';
import { registerEnumType } from '@nestjs/graphql';

export enum BoardRole {
  ADMIN = 'ADMIN',
  MODERATOR = 'MODERATOR',
  CONTRIBUTOR = 'CONTRIBUTOR',
}

registerEnumType(BoardRole, {
  name: 'BoardRole',
});

export enum Priority {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  EXTREME = 'EXTREME',
}

registerEnumType(Priority, {
  name: 'Priority',
});

export type User = InferSelectModel<typeof schema.users>;

export type Board = InferSelectModel<typeof schema.boards>;

export type List = InferSelectModel<typeof schema.lists>;

export type BoardUser = InferSelectModel<typeof schema.boardUsers>;

export type Task = InferSelectModel<typeof schema.tasks>;