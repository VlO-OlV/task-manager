import { ApolloClient, HttpLink } from "@apollo/client";
import { InMemoryCache } from "@apollo/client";
import { createFragmentRegistry } from "@apollo/client/cache";
import { BOARD_FRAGMENT, LIST_FRAGMENT, TASK_FRAGMENT, USER_FRAGMENT } from "./fragments";
import { SetContextLink } from "@apollo/client/link/context";
import { Cookies } from "react-cookie";
import { ErrorLink } from "@apollo/client/link/error";
import { CombinedGraphQLErrors } from "@apollo/client";
import { ApolloLink } from "@apollo/client";
import { GraphQLWsLink } from "@apollo/client/link/subscriptions";
import { createClient } from "graphql-ws";
import { OperationTypeNode } from "graphql";
import toast from "react-hot-toast";

const cache = new InMemoryCache({
  fragments: createFragmentRegistry(
    BOARD_FRAGMENT,
    LIST_FRAGMENT,
    TASK_FRAGMENT,
    USER_FRAGMENT,
  ),
});

const errorLink = new ErrorLink(({ error }) => {
  // TODO: Auth retry
  if (CombinedGraphQLErrors.is(error)) {
    error.errors.forEach(({ message, locations, path }) => {
      toast.error(message, {
        duration: 3000,
        position: 'bottom-right',
      });
      console.error(
        `[GraphQL error]: Message: ${message}, Location: ${locations}, Path: ${path}`
      )
    });
  } else {
    toast.error('Network error', {
      duration: 3000,
      position: 'bottom-right',
    });
    console.error("[Network error]:", error);
  }
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

const wsLink = new GraphQLWsLink(
  createClient({
    url: import.meta.env.VITE_WS_URL,
    connectionParams: {
      authorization: new Cookies().get('accessToken'),
    },
  })
);

const splitLink = ApolloLink.split(
  ({ operationType }) => {
    return operationType === OperationTypeNode.SUBSCRIPTION;
  },
  wsLink,
  authLink.concat(link),
);

export const client = new ApolloClient({
  cache: cache,
  link: ApolloLink.from([errorLink, splitLink]),
});