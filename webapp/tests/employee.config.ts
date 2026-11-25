import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.', testMatch: 'employee.spec.ts', timeout: 30_000,
  outputDir: '../test-results/employee',
  use: { baseURL: 'http://127.0.0.1:5175', browserName: 'chromium', trace: 'retain-on-failure' },
  webServer: { command: 'npm.cmd run dev -- --host 127.0.0.1 --port 5175 --strictPort --base /', cwd: '..', url: 'http://127.0.0.1:5175/employee/login', reuseExistingServer: false },
})
