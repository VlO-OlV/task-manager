import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { PgTable } from 'drizzle-orm/pg-core';
import { InferSelectModel, InferInsertModel, SQL } from 'drizzle-orm';
import * as schema from '../schema';
import { AnyPgTable } from 'drizzle-orm/pg-core';

export type DatabaseClient = NodePgDatabase<typeof schema>;
export type TransactionClient = Parameters<Parameters<DatabaseClient['transaction']>[0]>[0];

export abstract class AbstractRepository<
  Table extends PgTable,
  TableName extends keyof typeof schema,
  SelectModel = InferSelectModel<Table>,
  InsertModel = InferInsertModel<Table>,
> {
  protected constructor(
    protected readonly db: NodePgDatabase<typeof schema>,
    protected readonly table: Table,
    protected readonly tableName: TableName,
  ) {}

  protected getClient(tx?: TransactionClient): DatabaseClient | TransactionClient {
    return tx || this.db;
  }

  public async findMany(
    where?: SQL,
    limit: number = 100,
    offset: number = 0,
    orderBy?: SQL | SQL[],
    tx?: TransactionClient,
  ): Promise<SelectModel[]> {
    const orderArray = orderBy ? (Array.isArray(orderBy) ? orderBy : [orderBy]) : [];

    const result = await this.getClient(tx)
      .select()
      .from(this.table as AnyPgTable)
      .where(where)
      .limit(limit)
      .offset(offset)
      .orderBy(...orderArray);

    return result as SelectModel[];
  }

  public async findOne(
    where: SQL,
    tx?: TransactionClient,
  ): Promise<SelectModel | null> {
    const result = await this.getClient(tx)
      .select()
      .from(this.table as AnyPgTable)
      .where(where)
      .limit(1);

    return (result[0] as SelectModel) ?? null;
  }

  public async create(data: InsertModel, tx?: TransactionClient): Promise<SelectModel> {
    const result = await this.getClient(tx)
      .insert(this.table)
      .values(data as any)
      .returning();

    return result[0] as SelectModel;
  }

  public async updateOne(
    where: SQL,
    data: Partial<InsertModel>,
    tx?: TransactionClient,
  ): Promise<SelectModel> {
    const result = await this.getClient(tx)
      .update(this.table)
      .set(data as any)
      .where(where)
      .returning();

    return result[0] as SelectModel;
  }

  public async deleteMany(where: SQL, tx?: TransactionClient): Promise<number> {
    const result = await this.getClient(tx)
      .delete(this.table)
      .where(where)
      .returning();
      
    return (result as SelectModel[]).length;
  }

  public async deleteOne(where: SQL, tx?: TransactionClient): Promise<SelectModel> {
    const result = await this.getClient(tx)
      .delete(this.table)
      .where(where)
      .returning();

    return result[0] as SelectModel;
  }

  public async count(where: SQL, tx?: TransactionClient): Promise<number> {
    const result = await this.getClient(tx).$count(this.table as AnyPgTable, where);

    return result;
  }

  public async upsert(
    data: InsertModel,
    tx?: TransactionClient,
  ): Promise<SelectModel> {
    const result = await this.getClient(tx)
      .insert(this.table)
      .values(data as any)
      .onConflictDoUpdate({
        target: this.table?.['id'],
        set: { ...data },
      })
      .returning();

    return result[0] as SelectModel;
  }
}