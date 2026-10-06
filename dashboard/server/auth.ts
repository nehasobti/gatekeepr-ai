import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { getDb, schema } from './db';

const db = getDb();

export const auth = betterAuth({
  database: db
    ? drizzleAdapter(db, {
        provider: 'pg',
        schema: {
          user: schema.users,
          session: schema.sessions,
          account: schema.accounts,
          verification: schema.verifications,
        },
      })
    : undefined,
  secret: process.env.BETTER_AUTH_SECRET || 'gatekeeper-secret-dev-key-change-in-prod',
  emailAndPassword: {
    enabled: true,
  },
});
