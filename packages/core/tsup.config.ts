import { defineConfig } from 'tsup'

// Build the core to dual ESM + CJS with type declarations so both the new
// ESM/TS code and the current CommonJS server (app.js `require`) can consume it.
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  shims: true, // provide __dirname/__filename in the ESM output
  outExtension({ format }) {
    return { js: format === 'cjs' ? '.cjs' : '.js' }
  },
})
