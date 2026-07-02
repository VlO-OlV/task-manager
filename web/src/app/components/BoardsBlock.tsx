import BoardCard from './BoardCard';
import '../../assets/styles/BoardsBlock.css';
import { type BoardUser } from '../types/BoardUser';
import { useQuery } from '@apollo/client/react';
import { GET_MY_BOARD_USERS } from '../graphql/queries/boardUser';

function BoardsBlock () {

  const {
    data,
    loading: isBoardUsersFetching,
    refetch: refetchBoardUsers,
    error: fetchBoardUsersError,
  } = useQuery(GET_MY_BOARD_USERS);

  const boardUsers: BoardUser[] = data?.myBoardUsers ?? [];

  const renderBoards = (boardUsers: BoardUser[]) => {
    const boardBlocks = boardUsers.map((boardUser) => (<BoardCard boardId={boardUser.boardId} userRole={boardUser.userRole} refetchBoards={refetchBoardUsers} />))
    return boardBlocks;
  }

  if (fetchBoardUsersError) {
    // showMessage(getErrorMsg(fetchBoardUsersError as never));
    return (<></>);
  }
  
  return (
    <div className="boards-block">
      {
        !isBoardUsersFetching && renderBoards(boardUsers)
      }
    </div>
  );
}

export default BoardsBlock;