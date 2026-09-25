import { expect, test } from '@playwright/test'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('policy fleet filters server status and keeps the table usable on mobile', async ({ page }) => {
  const errors: string[] = []
  const requests: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.route('**/api/admin/console/policies**', async route => {
    const url = new URL(route.request().url())
    if (url.pathname.endsWith('/fleet')) {
      requests.push(url.search)
      const filtered = url.searchParams.get('compliance') === 'PARTIAL'
      await route.fulfill({ json: { data: [{
        id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        device_identifier: 'FLEET-01', display_name: 'Тестовый компьютер',
        agent_version: '3.2.70', online: true, policy_name: 'Основная',
        policy_version: 2, applied_version: 2, delivery_status: 'APPLIED',
        compliance: filtered ? 'PARTIAL' : 'COMPLIANT',
        acknowledged_at: '2026-09-25T12:00:00Z',
        activity_sensor: filtered ? 'STALE' : 'ACTIVE',
        browser_sensor: 'ACTIVE', dlp_sensor: 'UNAVAILABLE',
      }], total: filtered ? 51 : 1, limit: 50, offset: Number(url.searchParams.get('offset')) } })
      return
    }
    await route.fulfill({ json: url.pathname.endsWith('/assignments/default')
      ? { data: null } : { data: [], total: 0, limit: 50, offset: 0 } })
  })
  await page.route('**/api/admin/console/security/events**', route => route.fulfill({ json: {
    data: [], total: 0, limit: 50, offset: 0,
  } }))
  await page.route('**/api/admin/console/browser-sensor/release', route => route.fulfill({ json: null }))
  await page.goto('/admin/login')
  await page.getByLabel('Имя пользователя').fill('console-e2e')
  await page.getByLabel('Пароль').fill('console-e2e-password')
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByRole('navigation', { name: 'Основная навигация' }).getByRole('link', { name: 'Политики и DLP' }).click()
  const fleet = page.getByRole('heading', { name: 'Состояние политики по устройствам' }).locator('..').locator('..')
  await expect(fleet.getByRole('table').getByText('Тестовый компьютер')).toBeVisible()
  await fleet.getByLabel('Соответствие').selectOption('PARTIAL')
  await expect(fleet.getByRole('table').getByText('Частично соответствует')).toBeVisible()
  await expect(fleet.getByRole('table').getByText('Данные устарели')).toBeVisible()
  await expect(fleet.getByRole('table').getByText('Недоступен')).toBeVisible()
  expect(requests.some(query => query.includes('compliance=PARTIAL') && query.includes('offset=0'))).toBe(true)
  await page.screenshot({ path: join(tmpdir(), 'endpoint-policy-fleet-desktop.png'), fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(fleet.getByRole('heading', { name: 'Состояние политики по устройствам' })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
  await page.screenshot({ path: join(tmpdir(), 'endpoint-policy-fleet-mobile.png'), fullPage: true })
  expect(errors).toEqual([])
})
