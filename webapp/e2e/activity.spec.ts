import { expect, test } from '@playwright/test'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('administrator sees bounded current Activity and its mobile layout', async ({ page }) => {
  const browserErrors: string[] = []
  page.on('pageerror', error => browserErrors.push(error.message))
  page.on('console', message => { if (message.type() === 'error') browserErrors.push(message.text()) })
  await page.route('**/api/admin/console/devices/*/activity', async route => {
    await route.fulfill({ json: { data: {
      collected_at: '2026-09-25T11:59:00Z', last_observed_at: '2026-09-25T12:00:00Z',
      online: true, fresh: true,
      sections: {
        user_login: 'operator', session_state: 'ACTIVE', idle_seconds: 23,
        foreground: { process_name: 'chrome.exe', application_category: 'browser' },
        browser: { browser_family: 'chrome', domain: 'example.org',
          sensor_state: 'ACTIVE', extension_version: '0.1.0', last_seen_at: '2026-09-25T12:00:00Z' },
        window_title: 'MUST_NOT_LEAK',
      },
    } } })
  })

  await page.goto('/admin/login')
  await page.getByLabel('Имя пользователя').fill('console-e2e')
  await page.getByLabel('Пароль').fill('console-e2e-password')
  await page.getByRole('button', { name: 'Войти' }).click()
  await expect(page.getByRole('heading', { name: 'Состояние парка' })).toBeVisible()
  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Устройства' }).click()
  await page.getByRole('row').filter({ hasText: 'Тестовый компьютер' }).getByRole('link', { name: 'Открыть' }).click()
  await expect(page).toHaveURL(/\/admin\/devices\//)
  await expect(page.getByRole('heading', { name: 'Тестовый компьютер' })).toBeVisible()
  await page.getByRole('button', { name: 'Активность' }).click()

  const activity = page.getByRole('heading', { name: 'Активность' }).locator('..')
  await expect(activity.getByText('Активен')).toBeVisible()
  await expect(activity.getByText('23 с')).toBeVisible()
  await expect(activity.getByText('chrome.exe')).toBeVisible()
  await expect(activity.getByText('example.org')).toBeVisible()
  await expect(activity).not.toContainText('MUST_NOT_LEAK')
  await expect(page.locator('vite-error-overlay')).toHaveCount(0)
  await page.screenshot({ path: join(tmpdir(), 'endpoint-activity-console-e2e.png'), fullPage: true })

  await page.setViewportSize({ width: 390, height: 844 })
  await expect(activity.getByText('Активен')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
  await page.screenshot({ path: join(tmpdir(), 'endpoint-activity-console-mobile-e2e.png'), fullPage: true })
  expect(browserErrors).toEqual([])
})
