import { gql } from "@apollo/client";

export const TASK_FRAGMENT = gql`
  fragment TaskFragment on Task {
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
`;