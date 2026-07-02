import { gql } from "@apollo/client";

export const BOARD_FRAGMENT = gql`
  fragment BoardFragment on Board {
    id
    name
    createdAt
    updatedAt
  }
`;