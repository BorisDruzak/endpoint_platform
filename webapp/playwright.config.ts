import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  use: { baseURL: 'https://localhost:8765', browserName: 'chromium', ignoreHTTPSErrors: true },
  webServer: {
    command: 'python -m tests.browser.console_server',
    cwd: '..',
    url: 'https://localhost:8765/admin/login',
    ignoreHTTPSErrors: true,
    timeout: 30_000,
    reuseExistingServer: false,
  },
})
