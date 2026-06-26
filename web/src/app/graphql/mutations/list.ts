import { gql, type TypedDocumentNode } from "@apollo/client";
import type { CreateListData, UpdateListData } from "../../types/List";

export const CREATE_LIST: TypedDocumentNode<void, { data: CreateListData }> = gql`
  mutation CreateList($data: CreateListDto!) {
    createList(data: $data) {
      ...ListFragment
    }
  }
`;

export const UPDATE_LIST_BY_ID: TypedDocumentNode<void, { id: string, data: UpdateListData }> = gql`
  mutation UpdateListById($id: String!, $data: UpdateListDto!) {
    updateListById(listId: $id, data: $data) {
      ...ListFragment
    }
  }
`;

export const DELETE_LIST_BY_ID: TypedDocumentNode<void, { id: string }> = gql`
  mutation DeleteListById($id: String!) {
    deleteListById(listId: $id) {
      ...ListFragment
    }
  }
`;
