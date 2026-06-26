import { gql } from "@apollo/client";

export const LIST_FRAGMENT = gql`
  fragment ListFragment on List {
    id
    name
    boardId
    createdAt
    updatedAt
  }
`;