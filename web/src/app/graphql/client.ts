import { ApolloClient, HttpLink } from "@apollo/client";
import { InMemoryCache } from "@apollo/client";
import { createFragmentRegistry } from "@apollo/client/cache";
import { LIST_FRAGMENT, TASK_FRAGMENT, USER_FRAGMENT } from "./fragments";
import { SetContextLink } from "@apollo/client/link/context";
import { Cookies } from "react-cookie";

const cache = new InMemoryCache({
  fragments: createFragmentRegistry(
    LIST_FRAGMENT,
    TASK_FRAGMENT,
    USER_FRAGMENT,
  ),
});

const link = new HttpLink({ uri: import.meta.env.VITE_API_URL });

const authLink = new SetContextLink(({ headers }) => {
  const accessToken = new Cookies().get('accessToken');
  return {
    headers: {
      ...headers,
      authorization: accessToken ? `Bearer ${accessToken}` : "",
    },
  };
});

export const client = new ApolloClient({
  cache: cache,
  link: authLink.concat(link),
});