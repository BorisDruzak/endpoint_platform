import { expect, test } from '@playwright/test'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('administrator inspects a bounded browser SecurityEvent', async ({ page }) => {
  const browserErrors: string[] = []
  page.on('pageerror', error => browserErrors.push(error.message))
  page.on('console', message => { if (message.type() === 'error') browserErrors.push(message.text()) })
  await page.route('**/api/admin/console/browser-sensor/release', async route => {
    await route.fulfill({ json: {
      extension_version: '0.1.0', extension_id: 'abcdefghijklmnopabcdefghijklmnop',
      protocol_version: 1, source_revision: 'a'.repeat(40),
      artifact_sha256: 'b'.repeat(64), minimum_agent_version: '3.2.70',
      built_at: '2026-09-25T12:00:00Z', published_at: '2026-09-25T13:00:00Z',
      update_url: '/api/v1/browser-sensor/update.xml',
      artifact_url: '/api/v1/browser-sensor/releases/0.1.0/sensor.crx',
      signing_private_key: 'MUST_NOT_LEAK',
    } })
  })
  await page.route('**/api/admin/console/policies**', async route => {
    const url = new URL(route.request().url())
    await route.fulfill({ json: url.pathname.endsWith('/assignments/default')
      ? { data: null }
      : { data: [], total: 0, limit: 50, offset: 0 } })
  })
  await page.route('**/api/admin/console/security/events**', async route => {
    const url = new URL(route.request().url())
    if (url.pathname.endsWith('/event-1')) {
      await route.fulfill({ json: { data: {
        id: 'event-1', device_id: 'device-1', device_name: 'Тестовый компьютер',
        event_type: 'BROWSER_UPLOAD', channel: 'BROWSER', severity: 'INFO',
        occurred_at: '2026-09-25T12:00:00Z', received_at: '2026-09-25T12:00:01Z',
        user_login: 'operator', policy_id: 'policy-1', policy_version: 2,
        domain: 'example.org', metadata_valid: true,
        safe_metadata: { domain: 'example.org', origin: 'https://example.org',
          browser_family: 'yandex', file_count: 2, total_bytes: 4096,
          mime_categories: ['document'] },
      } } })
      return
    }
    await route.fulfill({ json: { data: [{
      id: 'event-1', device_id: 'device-1', device_name: 'Тестовый компьютер',
      event_type: 'BROWSER_UPLOAD', channel: 'BROWSER', severity: 'INFO',
      occurred_at: '2026-09-25T12:00:00Z', received_at: '2026-09-25T12:00:01Z',
      user_login: 'operator', policy_id: 'policy-1', policy_version: 2,
      domain: 'example.org', metadata_valid: true,
    }], total: 1, limit: 50, offset: 0 } })
  })
  await page.goto('/admin/login')
  await page.getByLabel('Имя пользователя').fill('console-e2e')
  await page.getByLabel('Пароль').fill('console-e2e-password')
  await page.getByRole('button', { name: 'Войти' }).click()
  await expect(page.getByRole('heading', { name: 'Состояние парка' })).toBeVisible()
  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Политики и DLP' }).click()
  await expect(page).toHaveURL(/\/admin\/security$/)
  await expect(page.getByRole('heading', { name: 'События безопасности' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Активная политика' })).toBeVisible()
  const release = page.getByRole('heading', { name: 'Browser Sensor' }).locator('..')
  await expect(release.getByText('0.1.0')).toBeVisible()
  await expect(release).not.toContainText('MUST_NOT_LEAK')
  await expect(page.getByRole('button', { name: 'Создать политику' })).toBeVisible()
  await expect(page.getByRole('table').getByText('Тестовый компьютер')).toBeVisible()
  await page.getByLabel('Канал').selectOption('BROWSER')
  await expect(page).toHaveURL(/channel=BROWSER/)
  await page.getByRole('table').getByRole('button', { name: 'Детали' }).click()
  const detail = page.getByRole('region', { name: 'Детали события' })
  await expect(detail.getByText('Яндекс Браузер')).toBeVisible()
  await expect(detail.getByText('Документ')).toBeVisible()
  await expect(detail.getByText('Аудит')).toBeVisible()
  await page.screenshot({ path: join(tmpdir(), 'endpoint-security-console-e2e.png'), fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByRole('heading', { name: 'События безопасности' })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
  await page.screenshot({ path: join(tmpdir(), 'endpoint-security-console-mobile-e2e.png'), fullPage: true })
  expect(browserErrors).toEqual([])
})
