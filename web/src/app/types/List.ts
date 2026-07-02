import type { Task } from "./Task";

export interface List {
    id: string,
    name: string,
    boardId: string,
    tasks: Task[],
    updatedAt: Date,
    createdAt: Date,
}

export interface CreateListData extends Omit<List, 'id' | 'tasks' | 'createdAt' | 'updatedAt'> {}

export interface UpdateListData extends Partial<Pick<CreateListData, 'name'>> {}