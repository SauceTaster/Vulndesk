import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

// util.js (the CVE transform layer) is required server-side by routes/onedoc.js
// and is plain CommonJS, so tests run in the Node environment.
export default defineConfig({
  resolve: {
    alias: {
      // Run tests against the @vulndesk/core TypeScript source (vitest transpiles
      // it) so no build step is needed mid-dev. The package's built dist is what
      // the CommonJS server consumes in production.
      '@vulndesk/core': fileURLToPath(new URL('./packages/core/src/index.ts', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.js'],
    // The routes-api suite spins an in-memory MongoDB; its startup can race.
    // A single retry keeps the integration tests reliable without masking
    // deterministic unit failures (those pass on the first attempt).
    retry: process.env.CI ? 2 : 1,
  },
})
