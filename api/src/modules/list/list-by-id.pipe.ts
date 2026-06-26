import { Injectable, PipeTransform } from "@nestjs/common";
import { InvalidEntityIdException } from "../../utils/exceptions/invalid-entity-id.exception";
import { ListService } from "./list.service";

@Injectable()
export class ListByIdPipe implements PipeTransform {
    constructor (
        private listService: ListService,
    ) {}

    async transform(listId: string) {
        const list = await this.listService.getById(listId);
        if (!list) {
            throw new InvalidEntityIdException('List');
        }
        return listId;
    }
}