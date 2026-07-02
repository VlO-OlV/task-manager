import { useParams } from 'react-router-dom';
import '../../assets/styles/OpenedBoardBlock.css';
import { type List } from '../types/List';
import ListBlock from './ListBlock';
import { useMutation, useQuery } from '@apollo/client/react';
import { GET_BOARD_LISTS } from '../graphql/queries/board';
import { CREATE_LIST } from '../graphql/mutations/list';

function OpenedBoardBlock () {
  const { boardId } = useParams();

  const { 
    data,
    loading: isListsFetching,
    refetch: refetchLists,
    error: fetchListsError,
  } = useQuery(GET_BOARD_LISTS, {
    variables: { id: boardId as string },
    skip: !boardId,
  });

  const [ createList ] = useMutation(CREATE_LIST);

  const lists: List[] = data?.board.lists ?? [];

  const addList = async () => {
    createList({
      variables: {
        data: {
          name: 'New List',
          boardId: boardId as string,
        },
      },
    })
      .then(() => {
        refetchLists();
      })
      .catch(() => {
        // showMessage(getErrorMsg(error as never));
      });
  };

  function renderLists(lists: List[]): React.ReactElement[] {
    const listBlocks = lists.map((list) => <ListBlock listData={list} refetchLists={refetchLists}/>)
    listBlocks.push(<button className="button-list" onClick={addList}>Create new list</button>);
    return listBlocks;
  }

  if (fetchListsError) {
    // showMessage(getErrorMsg(fetchListsError as never));
    return (<></>);
  }

  return (
    <div className="lists-block">
      {!isListsFetching && renderLists(lists)}
    </div>
  );
}

export default OpenedBoardBlock;