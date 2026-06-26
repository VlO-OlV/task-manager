import { 
  pgTable, 
  text, 
  boolean, 
  timestamp, 
  uuid, 
  pgEnum, 
  unique 
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

export const priority = pgEnum('priority', ['LOW', 'MEDIUM', 'HIGH', 'EXTREME']);
export const boardRole = pgEnum('board_role', ['ADMIN', 'MODERATOR', 'CONTRIBUTOR']);

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: text('email').notNull().unique(),
  password: text('password').notNull(),
  username: text('username'),
  firstName: text('firstName').notNull(),
  lastName: text('lastName').notNull(),
  isVerified: boolean('is_verified').notNull().default(false),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow().$onUpdate(() => new Date()),
});

export const boards = pgTable('boards', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow().$onUpdate(() => new Date()),
});

export const lists = pgTable('lists', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  boardId: uuid('board_id')
    .notNull()
    .references(() => boards.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow().$onUpdate(() => new Date()),
});

export const boardUsers = pgTable('board_users', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  boardId: uuid('board_id')
    .notNull()
    .references(() => boards.id, { onDelete: 'cascade' }),
  userRole: boardRole('user_role').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow().$onUpdate(() => new Date()),
}, (table) => ({
  userBoardUnique: unique().on(table.userId, table.boardId), 
}));

export const tasks = pgTable('tasks', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  deadline: timestamp('deadline'),
  listId: uuid('list_id')
    .notNull()
    .references(() => lists.id, { onDelete: 'cascade' }),
  priority: priority('priority').notNull(),
  assigneeId: uuid('assignee_id')
    .references(() => boardUsers.id),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow().$onUpdate(() => new Date()),
});

export const usersRelations = relations(users, ({ many }) => ({
  boardUsers: many(boardUsers),
}));

export const boardsRelations = relations(boards, ({ many }) => ({
  lists: many(lists),
  boardUsers: many(boardUsers),
}));

export const listsRelations = relations(lists, ({ one, many }) => ({
  board: one(boards, {
    fields: [lists.boardId],
    references: [boards.id],
  }),
  tasks: many(tasks),
}));

export const boardUsersRelations = relations(boardUsers, ({ one, many }) => ({
  user: one(users, {
    fields: [boardUsers.userId],
    references: [users.id],
  }),
  board: one(boards, {
    fields: [boardUsers.boardId],
    references: [boards.id],
  }),
  tasks: many(tasks),
}));

export const tasksRelations = relations(tasks, ({ one }) => ({
  list: one(lists, {
    fields: [tasks.listId],
    references: [lists.id],
  }),
  assignee: one(boardUsers, {
    fields: [tasks.assigneeId],
    references: [boardUsers.id],
  }),
}));