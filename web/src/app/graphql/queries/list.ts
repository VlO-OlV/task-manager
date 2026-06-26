import { gql, type TypedDocumentNode } from "@apollo/client";
import type { List } from "../../types/List";

export const GET_LIST_BY_ID: TypedDocumentNode<{ list: List }, { id: string }> = gql`
  query GetListById($id: String!) {
    list(listId: $id) {
      ...ListFragment
    }
  }
`;

export const GET_ALL_LISTS: TypedDocumentNode<{ lists: List[] }, void> = gql`
  query GetAllLists {
    lists {
      ...ListFragment
    }
  }
`;
