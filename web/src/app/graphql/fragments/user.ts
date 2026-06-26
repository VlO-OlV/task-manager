import { gql } from "@apollo/client";

export const USER_FRAGMENT = gql`
  fragment UserFragment on User {
    id
    email
    username
    firstName
    lastName
    isVerified
    createdAt
    updatedAt
  }
`;