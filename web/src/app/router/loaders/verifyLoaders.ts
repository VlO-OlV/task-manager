import type { Params } from "react-router-dom";
import { client } from "../../graphql/client";
import { VERIFY_EMAIL } from "../../graphql/mutations";

export const verifyEmailLoader = async ({ params }: { params: Params<string> }) => {
  const verifyEmail = await client.query({ query: VERIFY_EMAIL, variables: { userId: params.userId as string } });
  if (verifyEmail.error) {
    return null;
  }
  return verifyEmail.data;
}