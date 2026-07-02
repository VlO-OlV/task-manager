import { useEffect, useState } from 'react';
import '../../assets/styles/Modal.css';
import { type List } from '../types/List';
import { type Task } from '../types/Task';
import { Priority } from '../enums/PriorityEnum';
import getDateString from '../utils/getDateString';
import { formatEnum } from '../utils/formatEnum';
import { useMutation, useQuery } from '@apollo/client/react';
import { GET_LIST_BY_ID } from '../graphql/queries/list';
import { CREATE_TASK, UPDATE_TASK_BY_ID } from '../graphql/mutations/task';
import { useForm } from 'react-hook-form';

interface ModalProps {
  listId: string,
  taskData: Task,
  mode: number,
  refetchTasks: () => void,
  closeModal: () => void,
  changeMode: (mode: number) => void,
}

interface TaskFormValues {
  name: string;
  deadline: string;
  priority: Priority;
  description: string;
}

const toDateTimeLocalValue = (date: Date | string | undefined | null): string => {
  if (!date) {
    return '';
  }

  const parsedDate = typeof date === 'string' ? new Date(date) : date;
  if (Number.isNaN(parsedDate.getTime())) {
    return '';
  }

  const adjustedDate = new Date(parsedDate.getTime() - parsedDate.getTimezoneOffset() * 60000);
  return adjustedDate.toISOString().slice(0, 16);
};

function Modal({
  listId,
  taskData,
  mode,
  refetchTasks,
  closeModal,
  changeMode,
}: ModalProps) {

  const {
    data,
    loading: isListFetching,
    error: fetchListError,
  } = useQuery(GET_LIST_BY_ID, {
    variables: { id: listId },
  });

  const [updateTask] = useMutation(UPDATE_TASK_BY_ID);
  const [createTask] = useMutation(CREATE_TASK);

  const currentList: List | undefined = data?.list;

  const [isVisibleDropdown, setIsVisibleDropdown] = useState(false);

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    watch,
  } = useForm<TaskFormValues>({
    defaultValues: {
      name: '',
      deadline: '',
      priority: Priority.LOW,
      description: '',
    },
  });

  useEffect(() => {
    reset({
      name: mode === 2 ? taskData.name : '',
      deadline: mode === 2 ? toDateTimeLocalValue(taskData.deadline) : '',
      priority: mode === 2 ? taskData.priority : Priority.LOW,
      description: mode === 2 ? taskData.description ?? '' : '',
    });
  }, [mode, taskData, reset]);

  const selectedPriority = watch('priority');

  const changePriority = (priority: Priority) => {
    setValue('priority', priority, { shouldDirty: true });
    setIsVisibleDropdown(false);
  };

  const onSubmit = async (values: TaskFormValues) => {
    const payload = {
      name: values.name,
      description: values.description,
      deadline: values.deadline ? new Date(values.deadline) : null,
      listId,
      priority: values.priority,
    };

    if (mode === 2) {
      await updateTask({
        variables: {
          id: taskData.id,
          data: payload,
        },
      })
        .then(() => {
          refetchTasks();
          closeModal();
        })
        .catch(() => {
          // showMessage(getErrorMsg(error as never));
        });
      return;
    }

    await createTask({
      variables: {
        data: payload,
      },
    })
      .then(() => {
        refetchTasks();
        closeModal();
      })
      .catch(() => {
        // showMessage(getErrorMsg(error as never));
      });
  };

  if (fetchListError) {
    // showMessage(getErrorMsg(fetchListError as never));
    return (<></>);
  }

  return (
    <div className="modal-wrapper">
      <div className="modal">
        <div className="modal-header">
          <button className="modal-close" onClick={closeModal}></button>
        </div>
        {
          mode === 1 ?
            <div className="modal-body">
              <div className="modal-body-header">
                <h2 className="body-header_title">{taskData.name}</h2>
                <button className="body-header_button button-edit" onClick={() => { changeMode(2); }}>Edit task</button>
              </div>
              <div className="modal-body-info">
                <div className="info_block">
                  <span className="status_label">Status</span>
                  <p>{!isListFetching && currentList?.name}</p>
                </div>
                <div className="info_block">
                  <span className="deadline_label">Due date</span>
                  <p>{taskData.deadline ? getDateString(new Date(taskData.deadline)) : 'No deadline'}</p>
                </div>
                <div className="info_block">
                  <span className="priority_label">Priority</span>
                  <p>{formatEnum(taskData.priority)}</p>
                </div>
              </div>
              <div className="modal-body-description">
                <h3>Description</h3>
                <p>{taskData.description}</p>
              </div>
            </div>
            :
            <form action='' className="modal-body" onSubmit={handleSubmit(onSubmit)}>
              <div className="modal-body-header">
                <input type="text" placeholder="Task title" className="title_input" {...register('name', { required: true })} />
                {
                  mode === 2 ?
                    <button type="button" className="body-header_button button-cancel" onClick={() => { changeMode(1); }}>Cancel</button>
                    :
                    null
                }
              </div>
              <div className="modal-body-info">
                <div className="info_block">
                  <label className="status_label">Status</label>
                  <p>{!isListFetching && currentList?.name}</p>
                </div>
                <div className="info_block">
                  <label htmlFor="deadline" className="deadline_label">Due date</label>
                  <input type="datetime-local" className="deadline_input" {...register('deadline')} />
                </div>
                <div className="info_block">
                  <label htmlFor="priority" className="priority_label">Priority</label>
                  <div className="priority_select">
                    <select value={selectedPriority} {...register('priority')}>
                      <option value={Priority.LOW}>Low</option>
                      <option value={Priority.MEDIUM}>Medium</option>
                      <option value={Priority.HIGH}>High</option>
                      <option value={Priority.EXTREME}>Extreme</option>
                    </select>
                    <div className="select_input">
                      <button type="button" className={isVisibleDropdown ? 'select_input_button select_input_button-active' : 'select_input_button'} onClick={() => { setIsVisibleDropdown(!isVisibleDropdown); }}>{formatEnum(selectedPriority)}</button>
                      {
                        isVisibleDropdown ?
                          <div className="select_input_options">
                            <button type="button" onClick={() => { changePriority(Priority.LOW); }}>Low</button>
                            <button type="button" onClick={() => { changePriority(Priority.MEDIUM); }}>Medium</button>
                            <button type="button" onClick={() => { changePriority(Priority.HIGH); }}>High</button>
                            <button type="button" className="option_last" onClick={() => { changePriority(Priority.EXTREME); }}>Extreme</button>
                          </div>
                          :
                          null
                      }
                    </div>
                  </div>
                </div>
              </div>
              <div className="modal-body-description">
                <h3>Description</h3>
                <textarea placeholder="Description to the task" {...register('description')}></textarea>
              </div>
              <div className="modal-body-submit">
                {
                  mode === 2 ?
                    <input className="form_button-submit" type="submit" value="Update" />
                    :
                    <input className="form_button-submit" type="submit" value="Create" />
                }
              </div>
            </form>
        }
      </div>
    </div>
  );
}

export default Modal;
