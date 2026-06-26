export interface List {
    id: string,
    name: string,
    boardId: string,
    updatedAt: Date,
    createdAt: Date,
}

export interface CreateListData extends Omit<List, 'id' | 'createdAt' | 'updatedAt'> {}

export interface UpdateListData extends Partial<Pick<CreateListData, 'name'>> {}