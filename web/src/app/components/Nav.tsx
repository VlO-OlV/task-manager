import { Link } from 'react-router-dom';
import '../../assets/styles/Nav.css';

interface NavProps {
  title?: string,
  children?: any, 
}

function Nav({ title, children }: NavProps) {
  return (
    <div className="nav">
      <h1 className="title">{title ?? 'Tasklify'}</h1>
      <div className="pages-block">
        <Link to='/'><span>Home</span></Link>
        <Link to='/boards'><span>My boards</span></Link>
      </div>
      <div className="buttons-block">
        {children}
      </div>
    </div>
  );
}
export default Nav;