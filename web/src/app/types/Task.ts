import { Priority } from "../enums/PriorityEnum";

export interface Task {
    id: string,
    name: string,
    description: string,
    deadline: Date,
    listId: string,
    priority: Priority,
    assigneeId?: string,
    createdAt: Date,
    updatedAt: Date,
}

export interface CreateTaskData extends Omit<Task, 'id' | 'createdAt' | 'updatedAt'> {}

export interface UpdateTaskData extends Partial<CreateTaskData> {}