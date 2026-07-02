import TaskBlock from "./TaskBlock";
import '../../assets/styles/List.css';
import Menu from "./Menu";
import { useEffect, useState } from "react";
import Modal from "./Modal.tsx";
import { type Task } from "../types/Task";
import { type List } from '../types/List';
import { MenuModes } from '../enums/MenuModesEnum';
import { useMutation, useQuery } from '@apollo/client/react';
import { DELETE_LIST_BY_ID, UPDATE_LIST_BY_ID } from '../graphql/mutations/list';
import { GET_LIST_TASKS } from '../graphql/queries/list';
import { useForm } from 'react-hook-form';

interface ListBlockProps {
  listData: List,
  refetchLists: () => void,
}

function ListBlock({
  listData,
  refetchLists
}: ListBlockProps) {

  const {
    data,
    loading: isTasksFetching,
    refetch: refetchTasks,
    error: fetchTasksError
  } = useQuery(GET_LIST_TASKS, {
    variables: { id: listData.id },
  });
  
  const [updateList] = useMutation(UPDATE_LIST_BY_ID);
  const [deleteList] = useMutation(DELETE_LIST_BY_ID);

  const tasks: Task[] = data?.list.tasks ?? [];

  const [isMenuVisible, setIsMenuVisible] = useState(false);
  const [isEditingMode, setIsEditingMode] = useState(false);
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [modalMode, setModalMode] = useState(1);
  const [viewedTask, setViewedTask] = useState({});

  const {
    register,
    handleSubmit,
    setValue,
  } = useForm<{ name: string }>({
    defaultValues: {
      name: listData.name,
    },
  });

  useEffect(() => {
    setValue('name', listData.name);
  }, [listData.name, setValue]);

  const updateListName = async ({ name }: { name: string }) => {
    await updateList({ variables: { id: listData.id, data: { name } } })
      .then(() => {
        refetchLists();          
        setIsEditingMode(false);
      })
      .catch(() => {
        // showMessage(getErrorMsg(error as never));
      });
  };

  const openModal = (mode: number) => {
    setModalMode(mode);
    setIsModalVisible(true);
  }

  const renderTasks = (tasks: Task[]): React.ReactElement[] => {
    const taskBlocks = tasks.map((task) => <TaskBlock taskData={task} openModal={(mode: number) => { openModal(mode); setViewedTask(task); }} refetchTasks={refetchTasks} />);
    return taskBlocks;
  }

  const removeList = async (listId: string) => {
    await deleteList({ variables: { id: listId } })
      .then(() => {
        refetchLists();
      })
      .catch(() => {
        // showMessage(getErrorMsg(error as never));
      });
  };

  const handleDeleteList = () => {
    removeList(listData.id);
    setIsMenuVisible(false);
  }

  const handleEditList = () => {
    setIsEditingMode(true);
    setIsMenuVisible(false);
  }

  if (fetchTasksError) {
    // showMessage(getErrorMsg(fetchTasksError as never));
    return (<></>);
  }

  return (
    <div className="list">
      { isMenuVisible ? <Menu menuMode={MenuModes.LIST} handleDelete={handleDeleteList} handleEdit={handleEditList}/> : null }
      {
        isEditingMode ?
          <form action="" className="list-header list-header_form" onSubmit={handleSubmit(updateListName)}>
            <input type="text" placeholder="List name" {...register('name', { required: true })} />
            <div>
              <button type="button" className="form_button button-cancel" onClick={() => {setIsEditingMode(false);}}></button>
              <button type="submit" className="form_button button-submit"></button>
            </div>
          </form>
        :
          <div className="list-header">
            <h3 className="list-title">{listData.name}</h3>
            <div>
              <p>{!isTasksFetching && tasks.length}</p>
              <button className="list-menu" onClick={() => {setIsMenuVisible(!isMenuVisible)}}></button>
            </div>
          </div>
      }
      <button className="list-add-task" onClick={() => {openModal(3);}}>Add new card</button>
      {!isTasksFetching && renderTasks(tasks)}
      { isModalVisible ? <Modal closeModal={() => {setIsModalVisible(false);}} changeMode={(mode: number) => {setModalMode(mode);}} refetchTasks={refetchTasks} mode={modalMode} listId={listData.id} taskData={viewedTask as Task} /> : null }
    </div>
  );
}

export default ListBlock;