const { defineConfig, devices } = require('@playwright/test')

// E2E tests drive the real CVE editor in a browser via the standalone bundle
// (no DB/server needed). This locks the actual editor UX — the parity spec the
// React rewrite must match.
module.exports = defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:8788',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // Build the standalone bundle, then serve it. Incremental make is fast.
    command: 'make min && npx http-server standalone -p 8788 -c-1 --silent',
    url: 'http://127.0.0.1:8788/index.html',
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
})
