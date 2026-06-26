import { RouterProvider } from 'react-router-dom';
import { router } from './router/router';
import { ApolloProvider } from '@apollo/client/react';
import { ToastProvider } from './hooks/contexts/ToastContext';
import { CookiesProvider } from 'react-cookie';
import { client } from './graphql/client';

function App() {
  return (
    <ApolloProvider client={client}>
      <ToastProvider>
        <CookiesProvider>
          <RouterProvider router={router} />
        </CookiesProvider>
      </ToastProvider>
    </ApolloProvider>
  );
}

export default App;