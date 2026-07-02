import { Link, useNavigate } from 'react-router-dom';
import '../../assets/styles/AuthForm.css';
import { useCookies } from 'react-cookie';
import { useMutation } from '@apollo/client/react';
import { LOGIN, REGISTER } from '../graphql/mutations/auth';
import { useForm } from 'react-hook-form';

interface AuthFormProps {
  isLogin: boolean;
}

interface AuthFormValues {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
}

function AuthForm ({ isLogin }: AuthFormProps) {

  const [registerUser] = useMutation(REGISTER);
  const [login] = useMutation(LOGIN);

  const [, setAccessCookie] = useCookies(['accessToken']);

  const navigate = useNavigate();

  const {
    register,
    handleSubmit,
  } = useForm<AuthFormValues>();

  const onSubmit = async (values: AuthFormValues) => {
    if (isLogin) {
      login({
        variables: {
          data: {
            email: values.email,
            password: values.password,
          },
        },
      })
        .then(({ data }) => {
          const accessToken = data?.login.accessToken;
          if (!accessToken) {
            throw new Error('Access token was not returned by the server');
          }
          setAccessCookie('accessToken', accessToken, { maxAge: 86400 });
          navigate('/');
        })
        .catch(() => {
          // showMessage(getErrorMsg(error));
        });
    } else {
      await registerUser({
        variables: {
          data: {
            firstName: values.firstName,
            lastName: values.lastName,
            email: values.email,
            password: values.password,
          },
        },
      })
        .then(() => {
          navigate('/verifyEmail');
        })
        .catch(() => {
          // showMessage(getErrorMsg(error));
        });
    }
  };

  return (
    <div className="form-block">
      <form className='auth-form' onSubmit={handleSubmit(onSubmit)}>
        <h2>{ isLogin ? 'Log in' : 'Sign up'}</h2>
        {
          isLogin ?
            null
          :
          <>
            <div className='input-block'>
              <label htmlFor='firstName'>First name</label>
              <input type='text' {...register('firstName', { required: !isLogin })} />
            </div>
            <div className='input-block'>
              <label htmlFor='lastName'>Last name</label>
              <input type='text' {...register('lastName', { required: !isLogin })} />
            </div>
          </>
        }
        <div className='input-block'>
          <label htmlFor='email'>Email</label>
          <input type='text' {...register('email', { required: true })} />
        </div>
        <div className='input-block'>
          <label htmlFor='password'>Password</label>
          <input type='password' {...register('password', { required: true })} />
        </div>
        <button type='submit' className='form-button_submit'>{ isLogin ? 'Log in' : 'Create account' }</button>
        {
          isLogin ?
            <p>Not registered yet? <Link to='/signup'>Sign up</Link></p>
          :
            <p>Already have an account? <Link to='/login'>Log in</Link></p>
        }
      </form>
    </div>
  );
}

export default AuthForm;