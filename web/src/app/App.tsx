import { RouterProvider } from 'react-router-dom';
import { router } from './router/router';
import { ApolloProvider } from '@apollo/client/react';
import { CookiesProvider } from 'react-cookie';
import { client } from './graphql/client';
import { Toaster } from 'react-hot-toast';

function App() {
  return (
    <ApolloProvider client={client}>
        <CookiesProvider>
          <RouterProvider router={router} />
          <Toaster />
        </CookiesProvider>
    </ApolloProvider>
  );
}

export default App;