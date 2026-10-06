import { pgTable, text, timestamp, boolean, integer, numeric, jsonb, uuid } from 'drizzle-orm/pg-core';

// Better-Auth Core Tables
export const users = pgTable('users', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: boolean('email_verified').notNull().default(false),
  image: text('image'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

export const sessions = pgTable('sessions', {
  id: text('id').primaryKey(),
  expiresAt: timestamp('expires_at').notNull(),
  token: text('token').notNull().unique(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
});

export const accounts = pgTable('accounts', {
  id: text('id').primaryKey(),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: timestamp('access_token_expires_at'),
  refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
  scope: text('scope'),
  password: text('password'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

export const verifications = pgTable('verifications', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Gatekeeper Repositories
export const repositories = pgTable('repositories', {
  id: text('id').primaryKey(), // slug e.g. "org/payments-service"
  name: text('name').notNull(),
  platform: text('platform').notNull().default('github'), // "github" | "bitbucket" | "local"
  defaultBranch: text('default_branch').notNull().default('main'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// Gatekeeper Audit Runs
export const auditRuns = pgTable('audit_runs', {
  id: text('id').primaryKey(), // uuid or custom run id
  repoId: text('repo_id').notNull().references(() => repositories.id, { onDelete: 'cascade' }),
  prId: text('pr_id'),
  commitSha: text('commit_sha'),
  sourceBranch: text('source_branch'),
  targetBranch: text('target_branch'),
  verdict: text('verdict').notNull(), // "PASS" | "FAIL" | "ERROR" | "SKIPPED"
  model: text('model'),
  durationSeconds: numeric('duration_seconds'),
  inputTokens: integer('input_tokens').default(0),
  outputTokens: integer('output_tokens').default(0),
  cachedTokens: integer('cached_tokens').default(0),
  estimatedCostUsd: numeric('estimated_cost_usd').default('0'),
  summary: jsonb('summary'), // { critical, high, medium, low, info, total }
  metadata: jsonb('metadata'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// Findings Breakdown
export const findings = pgTable('findings', {
  id: text('id').primaryKey(), // finding fingerprint
  runId: text('run_id').notNull().references(() => auditRuns.id, { onDelete: 'cascade' }),
  file: text('file').notNull(),
  startLine: integer('start_line').notNull(),
  endLine: integer('end_line').notNull(),
  severity: text('severity').notNull(), // CRITICAL, HIGH, MEDIUM, LOW, INFO
  confidence: text('confidence').notNull(), // HIGH, MEDIUM, LOW
  category: text('category').notNull(), // SECRETS, INJECTION, AUTH, etc.
  title: text('title').notNull(),
  explanation: text('explanation').notNull(),
  suggestedFix: text('suggested_fix'),
  source: text('source').default('claude'), // "claude" | "semgrep" | "bandit" | etc.
  cwe: text('cwe'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});
