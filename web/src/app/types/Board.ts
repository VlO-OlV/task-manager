import type { BoardUser } from "./BoardUser";
import type { List } from "./List";

export interface Board {
  id: string,
  name: string,
  boardUsers: BoardUser[],
  lists: List[],
  createdAt: Date,
  updatedAt: Date,
}

export interface CreateBoardData extends Omit<Board, 'id' | 'boardUsers' | 'lists' | 'createdAt' | 'updatedAt'> {}

export interface UpdateBoardData extends Partial<CreateBoardData> {}