import { gql, type TypedDocumentNode } from "@apollo/client";
import type { BoardUser } from "../../types/BoardUser";

export const GET_MY_BOARD_USERS: TypedDocumentNode<{ myBoardUsers: BoardUser[] }, void> = gql`
  query GetMyBoardUsers {
    myBoardUsers {
      id
      userId
      boardId
      userRole
      createdAt
      updatedAt
    }
  }
`;