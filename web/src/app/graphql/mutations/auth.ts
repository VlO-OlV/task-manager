import { gql, type TypedDocumentNode } from "@apollo/client";
import type { LoginData, LoginResponse, RegisterData } from "../../types/Auth";

export const LOGIN: TypedDocumentNode<{ login: LoginResponse }, { data: LoginData }> = gql`
  mutation Login($data: LoginDto!) {
    login(data: $data) {
      accessToken
    }
  }
`;

export const REGISTER: TypedDocumentNode<void, { data: RegisterData }> = gql`
  mutation Register($data: CreateUserDto!) {
    register(data: $data)
  }
`;

export const VERIFY_EMAIL: TypedDocumentNode<void, { userId: string }> = gql`
  mutation VerifyEmail($userId: String!) {
    verifyEmail(userId: $userId) {
      ...UserFragment
    }
  }
`;
