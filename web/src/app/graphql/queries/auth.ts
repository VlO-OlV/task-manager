import { gql, type TypedDocumentNode } from "@apollo/client";
import type { User } from "../../types/User";

export const GET_ME: TypedDocumentNode<{ me: User }, void> = gql`
  query GetMe {
    me {
      ...UserFragment
    }
  }
`;