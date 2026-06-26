import { Provider } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { drizzle, NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from './schema';

export const DATABASE_CLIENT = 'DATABASE_CLIENT';

export const DatabaseProvider: Provider = {
  provide: DATABASE_CLIENT,
  inject: [ConfigService],
  useFactory: async (configService: ConfigService) => {
    const databaseUrl = configService.get<string>('DATABASE_URL');
    const pool = new Pool({
      connectionString: databaseUrl,
    });

    return drizzle(pool, { schema }) as NodePgDatabase<typeof schema>;
  },
};