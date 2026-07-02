import { Link } from 'react-router-dom';
import Nav from '../components/Nav';
import AuthForm from '../components/AuthForm';

function SignupPage () {

  return (
    <>
      <Nav>
        <Link to='/login'><button className='button button-login'>Log in</button></Link>
      </Nav>
      <main>
        <AuthForm isLogin={false}/>
      </main>
    </>
  );
}

export default SignupPage;