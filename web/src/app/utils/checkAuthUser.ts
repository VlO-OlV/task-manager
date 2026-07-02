import { Cookies } from 'react-cookie';
import { client } from '../graphql/client';
import { GET_ME } from '../graphql/queries';

const checkAuthUser = async () => {
  try {
    const getMe = await client.query({ query: GET_ME, fetchPolicy: 'network-only' });
    const accessCookie = new Cookies().get('accessToken');
    if (getMe.error || !accessCookie) {
      return false;
    }
    return getMe.data?.me;
  } catch(err) {
    return false;
  }
}

export default checkAuthUser;