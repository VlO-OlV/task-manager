import { useEffect, useState } from 'react';
import '../../assets/styles/BoardCard.css';
import { BoardRole } from '../enums/BoardRoleEnum';
import { type Board } from '../types/Board';
import { formatEnum } from '../utils/formatEnum';
import getDateString from '../utils/getDateString';
import Menu from './Menu';
import { useNavigate } from 'react-router-dom';
import { MenuModes } from '../enums/MenuModesEnum';
import { useMutation, useQuery } from '@apollo/client/react';
import { GET_BOARD_BY_ID } from '../graphql/queries/board';
import { DELETE_BOARD_BY_ID, UPDATE_BOARD_BY_ID } from '../graphql/mutations/board';
import { useForm } from 'react-hook-form';

interface BoardCardProps {
  boardId: string,
  userRole: BoardRole,
  refetchBoards: () => void,
}

function BoardCard ({ boardId, userRole, refetchBoards }: BoardCardProps) {

  const {
    data,
    loading: isBoardFetching,
    refetch: refetchBoard,
    error: fetchBoardError,
  } = useQuery(GET_BOARD_BY_ID, {
    variables: { id: boardId },
  });

  const board: Board | undefined = data?.board;

  const [updateBoard] = useMutation(UPDATE_BOARD_BY_ID);
  const [deleteBoard] = useMutation(DELETE_BOARD_BY_ID);

  const navigate = useNavigate();

  const [isMenuVisible, setIsMenuVisible] = useState(false);
  const [isEditingMode, setIsEditingMode] = useState(false);

  const {
    register,
    handleSubmit,
    setValue,
  } = useForm<{ name: string }>({
    defaultValues: {
      name: '',
    },
  });

  const updateBoardName = async ({ name }: { name: string }) => {
    await updateBoard({ variables: { id: boardId, data: { name } } })
      .then(() => {
        refetchBoard();
        setIsEditingMode(false);
      })
      .catch(() => {
        // showMessage(getErrorMsg(error as never));
      });
  };

  const removeBoard = async (id: string) => {
    await deleteBoard({ variables: { id } })
      .then(() => {
        refetchBoards();
      })
      .catch(() => {
        // showMessage(getErrorMsg(error as never));
      })
  };

  const handleDeleteBoard = () => {
    removeBoard(boardId);
    setIsMenuVisible(false);
  }

  const handleEditBoard = () => {
    setIsEditingMode(true);
    setIsMenuVisible(false);
  }

  useEffect(() => {
    if (board) {
      setValue('name', board.name);
    }
  }, [board, setValue]);

  if (fetchBoardError) {
    // showMessage(getErrorMsg(fetchBoardError as never));
    return (<></>);
  }

  return (
    <div className="board-card" onClick={() => {navigate(`/boards/${boardId}`)}}>
      { isMenuVisible ? <Menu menuMode={MenuModes.BOARD} handleDelete={handleDeleteBoard} handleEdit={handleEditBoard}/> : null }
      {
        isEditingMode ?
          <form action="" className="board-card-header board-header_form" onSubmit={handleSubmit(updateBoardName)} onClick={(e) => {e.stopPropagation();}}>
            <input type="text" placeholder="Board name" {...register('name', { required: true })} />
            <div>
              <button type="button" className="form_button button-cancel" onClick={() => {setIsEditingMode(false);}}></button>
              <button type="submit" className="form_button button-submit"></button>
            </div>
          </form>
        :
          <div className="board-card-header">
            <h3>{!isBoardFetching && board?.name}</h3>
            <button className="board-menu" onClick={(e) => {e.stopPropagation(); setIsMenuVisible(!isMenuVisible);}}></button>
          </div>
      }
      <div className="board-card-details">
        <p className='board-user-role'>{formatEnum(userRole)}</p>
        <p className='last-updated'>{!isBoardFetching && board?.updatedAt ? getDateString(new Date(board.updatedAt)) : ''}</p>
      </div>
    </div>
  );
}

export default BoardCard;