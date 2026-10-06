import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';

const connectionString = process.env.DATABASE_URL || '';

let client: postgres.Sql | null = null;
let dbInstance: ReturnType<typeof drizzle> | null = null;

export function getDb() {
  if (!connectionString) {
    return null;
  }
  if (!client) {
    client = postgres(connectionString, { max: 10 });
    dbInstance = drizzle(client, { schema });
  }
  return dbInstance;
}

export { schema };
