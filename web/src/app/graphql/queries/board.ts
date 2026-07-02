import { gql, type TypedDocumentNode } from "@apollo/client";
import type { Board } from "../../types/Board";
import type { List } from "../../types/List";

type BoardWithLists = Board & { lists: List[] };

export const GET_BOARD_BY_ID: TypedDocumentNode<{ board: Board }, { id: string }> = gql`
  query GetBoardById($id: String!) {
    board(boardId: $id) {
      id
      name
      createdAt
      updatedAt
      boardUsers {
        id
        userId
        boardId
        userRole
        createdAt
        updatedAt
      }
    }
  }
`;

export const GET_BOARD_LISTS: TypedDocumentNode<{ board: BoardWithLists }, { id: string }> = gql`
  query GetBoardLists($id: String!) {
    board(boardId: $id) {
      id
      lists {
        id
        name
        boardId
        createdAt
        updatedAt
      }
    }
  }
`;