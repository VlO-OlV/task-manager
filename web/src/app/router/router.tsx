import { createBrowserRouter } from 'react-router-dom';
import HomePage from '../pages/HomePage';
import LoginPage from '../pages/LoginPage';
import SignupPage from '../pages/SignupPage';
import BoardPage from '../pages/BoardPage';
import ProfilePage from '../pages/ProfilePage';
import VerifyPage from '../pages/VerifyPage';
import { userAuthenticatedLoader, userNotAuthenticatedLoader } from './loaders/authLoaders';
import CheckEmailBlock from '../components/CheckEmailBlock';
import SuccessBlock from '../components/SuccessBlock';
import { verifyEmailLoader } from './loaders/verifyLoaders';
import BoardsBlock from '../components/BoardsBlock';
import OpenedBoardBlock from '../components/OpenedBoardBlock';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <HomePage />,
  },
  {
    path: '/login',
    element: <LoginPage />,
    loader: userNotAuthenticatedLoader,
  },
  {
    path: '/signup',
    element: <SignupPage />,
    loader: userNotAuthenticatedLoader,
  },
  {
    path: '/profile',
    element: <ProfilePage />,
    loader: userAuthenticatedLoader,
  },
  {
    path: '/verifyEmail',
    element: <VerifyPage/>,
    loader: userNotAuthenticatedLoader,
    children: [
      {
        path: ':userId',
        element: <SuccessBlock/>,
        loader: verifyEmailLoader,
      },
      {
        index: true,
        element: <CheckEmailBlock/>,
      }
    ],
  },
  { 
    path: '/boards',
    element: <BoardPage />,
    loader: userAuthenticatedLoader,
    children: [
      {
        path: ':boardId',
        element: <OpenedBoardBlock/>,
      },
      {
        index: true,
        element: <BoardsBlock/>,
      }
    ],
  },
]);