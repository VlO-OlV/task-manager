import { gql, type TypedDocumentNode } from "@apollo/client";
import type { CreateTaskData, UpdateTaskData } from "../../types/Task";

export const CREATE_TASK: TypedDocumentNode<void, { data: CreateTaskData }> = gql`
  mutation CreateTask($data: CreateTaskDto!) {
    createTask(data: $data) {
      ...TaskFragment
    }
  }
`;

export const UPDATE_TASK_BY_ID: TypedDocumentNode<void, { id: string, data: UpdateTaskData }> = gql`
  mutation UpdateTaskById($id: String!, $data: UpdateTaskDto!) {
    updateTaskById(taskId: $id, data: $data) {
      ...TaskFragment
    }
  }
`;

export const DELETE_TASK_BY_ID: TypedDocumentNode<void, { id: string }> = gql`
  mutation DeleteTaskById($id: String!) {
    deleteTaskById(taskId: $id) {
      ...TaskFragment
    }
  }
`;
