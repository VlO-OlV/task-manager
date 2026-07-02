import AuthForm from '../components/AuthForm';
import Nav from '../components/Nav';
import { Link } from 'react-router-dom';

function LoginPage () {
  return (
    <>
      <Nav>
        <Link to='/signup'><button className='button button-signup'>Sign up</button></Link>
      </Nav>
      <main>
        <AuthForm isLogin={true} />
      </main>
    </>
  );
}

export default LoginPage;