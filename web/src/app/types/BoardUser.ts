import { BoardRole } from '../enums/BoardRoleEnum';

export interface BoardUser {
  id: string,
  userId: string,
  boardId: string,
  userRole: BoardRole,
  createdAt: Date,
  updatedAt: Date,
}