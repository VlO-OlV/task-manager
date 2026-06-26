import { SetMetadata } from '@nestjs/common';
import { BoardRole } from '../../database/types';

export const BoardRoles = (...boardRoles: BoardRole[]) => SetMetadata('boardRoles', boardRoles);