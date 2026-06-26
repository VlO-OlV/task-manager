import { gql, type TypedDocumentNode } from "@apollo/client";
import type { Task } from "../../types/Task";

export const GET_TASK_BY_ID: TypedDocumentNode<{ task: Task }, { id: string }> = gql`
  query GetTaskById($id: String!) {
    task(taskId: $id) {
      ...TaskFragment
    }
  }
`;

export const GET_ALL_TASKS: TypedDocumentNode<{ tasks: Task[] }, void> = gql`
  query GetAllTasks {
    tasks {
      ...TaskFragment
    }
  }
`;
