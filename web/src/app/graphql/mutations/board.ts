import { gql, type TypedDocumentNode } from "@apollo/client";
import type { CreateBoardData, UpdateBoardData } from "../../types/Board";

export const CREATE_BOARD: TypedDocumentNode<void, { data: CreateBoardData }> = gql`
  mutation CreateBoard($data: CreateListDto!) {
    createBoard(data: $data) {
      ...BoardFragment
    }
  }
`;

export const UPDATE_BOARD_BY_ID: TypedDocumentNode<void, { id: string; data: UpdateBoardData }> = gql`
  mutation UpdateBoardById($id: String!, $data: UpdateListDto!) {
    updateBoardById(boardId: $id, data: $data) {
      ...BoardFragment
    }
  }
`;

export const DELETE_BOARD_BY_ID: TypedDocumentNode<void, { id: string }> = gql`
  mutation DeleteBoardById($id: String!) {
    deleteBoardById(listId: $id) {
      ...BoardFragment
    }
  }
`;