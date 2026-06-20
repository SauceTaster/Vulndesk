import { defineConfig } from 'drizzle-kit'

// `generate` diffs the schema into committed SQL (no DB needed). `migrate`
// applies them. We never `push` to anything but throwaway dev DBs (ADR-0001).
export default defineConfig({
  schema: './src/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
})
