import { expect, test } from '@playwright/test'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('device policy tab distinguishes overall compliance from live sensor health', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.route('**/api/admin/console/policies/devices/*/status', route => route.fulfill({ json: {
    data: {
      policy_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', policy_version: 1,
      policy_version_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      browser_required: true, deployment_mode: 'agent_managed', delivery_status: 'APPLIED',
      acknowledged_at: '2026-09-25T12:00:00Z', compliance: 'PARTIAL',
      activity_sensor: 'STALE', browser_sensor: 'ACTIVE', dlp_sensor: 'UNAVAILABLE',
      browser_compliance: 'COMPLIANT', observed_at: '2026-09-25T12:00:00Z',
      browsers: ['chrome', 'yandex'].map(browser_family => ({
        browser_family, browser_state: browser_family === 'chrome' ? 'DETECTED' : 'ABSENT',
        running_state: browser_family === 'chrome' ? 'RUNNING' : 'UNKNOWN',
        policy_owner: browser_family === 'chrome' ? 'ENDPOINT' : 'NONE',
        installation_policy_state: browser_family === 'chrome' ? 'APPLIED' : 'NOT_APPLIED',
        effective_policy_state: browser_family === 'chrome' ? 'APPLIED' : 'UNKNOWN',
        native_host_state: 'READY', extension_version: browser_family === 'chrome' ? '0.1.0' : null,
        extension_install_type: browser_family === 'chrome' ? 'ADMIN' : 'UNKNOWN',
        extension_last_seen_at: browser_family === 'chrome' ? '2026-09-25T12:00:00Z' : null,
        last_running_at: browser_family === 'chrome' ? '2026-09-25T12:00:00Z' : null,
        compliance_state: browser_family === 'chrome' ? 'ACTIVE' : 'NOT_APPLICABLE',
        reason: browser_family === 'chrome' ? null : 'BROWSER_ABSENT',
      })),
    },
  } }))

  await page.goto('/admin/login')
  await page.getByLabel('Имя пользователя').fill('console-e2e')
  await page.getByLabel('Пароль').fill('console-e2e-password')
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Устройства' }).click()
  await page.getByRole('row').filter({ hasText: 'Тестовый компьютер' }).getByRole('link', { name: 'Открыть' }).click()
  await page.getByRole('button', { name: 'Политика и DLP' }).click()
  const summary = page.getByRole('heading', { name: 'Политика и датчики' }).locator('..')
  await expect(summary.locator('div').filter({ hasText: 'Общее соответствие' }).first()).toContainText('Частично соответствует')
  await expect(summary.locator('div').filter({ hasText: 'Датчик активности' }).first()).toContainText('Данные устарели')
  await expect(summary.locator('div').filter({ hasText: 'DLP' }).first()).toContainText('Недоступен')
  await expect(summary.locator('div').filter({ hasText: 'Соответствие браузеров' }).first()).toContainText('Соответствует')
  await expect(page.getByRole('heading', { name: 'Chrome' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Яндекс Браузер' })).toBeVisible()
  await expect(page.locator('vite-error-overlay')).toHaveCount(0)
  await page.screenshot({ path: join(tmpdir(), 'endpoint-policy-status-desktop.png'), fullPage: true })

  await page.setViewportSize({ width: 390, height: 844 })
  await expect(summary.getByText('Частично соответствует')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
  await page.screenshot({ path: join(tmpdir(), 'endpoint-policy-status-mobile.png'), fullPage: true })
  expect(errors).toEqual([])
})
