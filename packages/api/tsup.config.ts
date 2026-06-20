import { defineConfig } from 'tsup'

// Build the app (library: exports `app` + `AppType` for tests and the RPC client)
// and the node server entry. Deps (@vulndesk/core, hono, scalar) stay external.
export default defineConfig({
  entry: ['src/app.ts', 'src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  shims: true,
})
