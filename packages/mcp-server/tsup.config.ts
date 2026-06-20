import { defineConfig } from 'tsup'

// The MCP server ships as an ESM Node bin. @vulndesk/core and the MCP SDK stay
// external (resolved from node_modules at runtime).
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  shims: true,
  // The shebang is preserved from src/index.ts; do not also add it as a banner
  // (that produced a duplicate shebang on line 2 → syntax error).
})
