import '../../assets/styles/ProfileBlock.css';
import { type User } from '../types/User';
import { useForm } from 'react-hook-form';

interface ProfileBlockProps {
  userData: User;
}

interface GeneralProfileFormValues {
  firstName: string;
  lastName: string;
}

interface SecurityFormValues {
  password: string;
  newPassword: string;
  claimPassword: string;
}

function ProfileBlock ({ userData }: ProfileBlockProps) {

  const { register: registerGeneral, handleSubmit: handleGeneralSubmit } = useForm<GeneralProfileFormValues>({
    defaultValues: {
      firstName: userData.firstName,
      lastName: userData.lastName,
    },
  });

  const { register: registerSecurity, handleSubmit: handleSecuritySubmit, reset: resetSecurityForm } = useForm<SecurityFormValues>();

  const handleGeneralFormSubmit = (_values: GeneralProfileFormValues) => {
    // TODO: Connect profile update mutation when available.
  };

  const handleSecurityFormSubmit = (_values: SecurityFormValues) => {
    // TODO: Connect password update mutation when available.
    resetSecurityForm();
  };

  return (
    <div className="profile-block">
      <div className="profile-header">
        <div className="profile-image"></div>
      </div>
      <div className="profile-data-block">
        <h3 className="block-title">Email</h3>
        <p className="email">{userData.email}</p>
      </div>
      <div className="profile-data-block">
        <h3 className="block-title">General</h3>
        <form onSubmit={handleGeneralSubmit(handleGeneralFormSubmit)}>
          <div className="profile-form-inputs">
            <div className="input-block">
              <label htmlFor="firstName">First name</label>
              <input type="text" {...registerGeneral('firstName', { required: true })} />
            </div>
            <div className="input-block">
              <label htmlFor="lastName">Last name</label>
              <input type="text" {...registerGeneral('lastName', { required: true })} />
            </div>
          </div>
          <button type="submit" className='form-button_submit'>Update data</button>
        </form>
      </div>
      <div className="profile-data-block">
        <h3 className="block-title">Security</h3>
        <form onSubmit={handleSecuritySubmit(handleSecurityFormSubmit)}>
          <div className="profile-form-inputs">
            <div className="input-block">
              <label htmlFor="password">Current password</label>
              <input type="password" {...registerSecurity('password', { required: true })} />
            </div>
            <div className="input-block"></div>
            <div className="input-block">
              <label htmlFor="newPassword">New password</label>
              <input type="password" {...registerSecurity('newPassword', { required: true })} />
            </div>
            <div className="input-block">
              <label htmlFor="claimPassword">Claim new password</label>
              <input type="password" {...registerSecurity('claimPassword', { required: true })} />
            </div>
          </div>
          <button type="submit" className='form-button_submit'>Change password</button>
        </form>
      </div>
    </div>
  );
}

export default ProfileBlock;