import '../../assets/styles/Menu.css'
import { MenuModes } from '../enums/MenuModesEnum';

interface MenuProps {
  handleEdit: () => void,
  handleDelete: () => void,
  menuMode: MenuModes,
}

function Menu({
  handleDelete,
  handleEdit,
  menuMode,
}: MenuProps) {

  return (
    <div className={`menu menu-${menuMode}`} onClick={(e) => {e.stopPropagation();}}>
      <button className="menu-button-edit" onClick={handleEdit}>Edit</button>
      <button className="menu-button-delete" onClick={handleDelete}>Delete</button>
    </div>
  );
}

export default Menu;