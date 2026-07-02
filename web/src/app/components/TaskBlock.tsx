import { useState } from 'react';
import '../../assets/styles/Task.css';
import Menu from './Menu';
import { type List } from '../types/List';
import { type Task } from '../types/Task';
import getDateString from '../utils/getDateString';
import { formatEnum } from '../utils/formatEnum';
import { useParams } from 'react-router-dom';
import { MenuModes } from '../enums/MenuModesEnum';
import { useMutation, useQuery } from '@apollo/client/react';
import { GET_BOARD_LISTS } from '../graphql/queries/board';
import { DELETE_TASK_BY_ID, UPDATE_TASK_BY_ID } from '../graphql/mutations/task';

interface TaskBlockProps {
  refetchTasks: () => void,
  taskData: Task,
  openModal: (mode: number) => void,
}

function TaskBlock({
  refetchTasks,
  taskData,
  openModal,
}: TaskBlockProps) {

  const { boardId } = useParams();

  const {
    data,
    error: fetchListsError,
  } = useQuery(GET_BOARD_LISTS, {
    variables: { id: boardId as string },
    skip: !boardId,
  });

  const [deleteTask] = useMutation(DELETE_TASK_BY_ID);
  const [updateTask] = useMutation(UPDATE_TASK_BY_ID);

  const lists: List[] = data?.board.lists ?? [];

  const [isVisibleDropdown, setIsVisibleDropdown] = useState(false);
  const [isMenuVisible, setIsMenuVisible] = useState(false);

  const removeTask = async (taskId: string) => {
    await deleteTask({ variables: { id: taskId } })
      .then(() => {
        refetchTasks();
      })
      .catch(() => {
        // showMessage(getErrorMsg(error as never));
      });
  };

  const handleDeleteTask = () => {
    removeTask(taskData.id);
    setIsMenuVisible(false);
  }

  const handleEditTask = () => {
    openModal(2);
    setIsMenuVisible(false);
  }

  const moveTask = async (targetListId: string) => {
    await updateTask({
      variables: {
        id: taskData.id,
        data: {
          name: taskData.name,
          description: taskData.description,
          deadline: taskData.deadline,
          listId: targetListId,
          priority: taskData.priority,
          assigneeId: taskData.assigneeId,
        },
      },
    })
      .then(() => {
        refetchTasks();
      })
      .catch(() => {
        // showMessage(getErrorMsg(error as never));
      });
  };

  const renderListOptions = (lists: List[]): React.ReactElement[] => {
    const filteredLists = lists.filter((list) => list.id !== taskData.listId);
    const listOptions = filteredLists.map((list, index) => (<button className={`task-dropdown-content-button ${index === filteredLists.length-1 ? 'lastList' : ''}`} onClick={() => {moveTask(list.id);}}>{list.name}</button>));
    return listOptions;
  }

  if (fetchListsError) {
    // showMessage(getErrorMsg(fetchListsError as never));
    return (<></>);
  }

  return (
    <div className="task" onClick={() => {openModal(1);}}>
      { isMenuVisible ? <Menu menuMode={MenuModes.TASK} handleDelete={handleDeleteTask} handleEdit={handleEditTask}/> : null }
      <div className="task-header">
        <h3 className="task-title">{taskData.name}</h3>
        <button className="task-menu" onClick={(e) => {e.stopPropagation(); setIsMenuVisible(!isMenuVisible)}}></button>
      </div>
      <p className="task-description">{taskData.description}</p>
      <span className="task-deadline">{taskData.deadline ? getDateString(new Date(taskData.deadline)) : 'No deadline'}</span>
      <span className="task-priority">{formatEnum(taskData.priority)}</span>
      <div className="task-dropdown" onClick={(e) => {e.stopPropagation();}}>
        <button className={ isVisibleDropdown ? "task-dropdown-button task-dropdown-button_active" : "task-dropdown-button"} onClick={ () => {setIsVisibleDropdown(!isVisibleDropdown)} }>Move to:</button>
        { isVisibleDropdown ? 
        <div className="task-dropdown-content">
          {renderListOptions(lists)}
        </div> : null }
      </div>
    </div>
  );
}

export default TaskBlock;