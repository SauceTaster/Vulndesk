import { defineConfig } from 'vitest/config'

// util.js (the CVE transform layer) is required server-side by routes/onedoc.js
// and is plain CommonJS, so tests run in the Node environment.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.js'],
  },
})
