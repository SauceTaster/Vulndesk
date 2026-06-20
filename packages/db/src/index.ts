import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import * as schema from './schema.js'

export * from './schema.js'
export { schema }
export * from './migrate.js'
export * from './repository.js'

/** A Drizzle database bound to the Vulndesk schema. */
export type Database = ReturnType<typeof createDb>

/** Connect to Postgres (postgres.js) with the Vulndesk schema bound. */
export function createDb(connectionString: string, options?: { max?: number }) {
  const client = postgres(connectionString, { max: options?.max ?? 10 })
  return drizzle(client, { schema })
}
