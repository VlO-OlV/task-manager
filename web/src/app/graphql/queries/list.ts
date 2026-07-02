import { gql, type TypedDocumentNode } from "@apollo/client";
import type { List } from "../../types/List";
import type { Task } from "../../types/Task";

type ListWithTasks = List & { tasks: Task[] };

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

export const GET_LIST_TASKS: TypedDocumentNode<{ list: ListWithTasks }, { id: string }> = gql`
  query GetListTasks($id: String!) {
    list(listId: $id) {
      id
      tasks {
        id
        name
        description
        deadline
        listId
        priority
        assigneeId
        createdAt
        updatedAt
      }
    }
  }
`;
