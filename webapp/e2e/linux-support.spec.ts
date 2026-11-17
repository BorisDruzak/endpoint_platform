import { expect, test } from '@playwright/test'

const deviceId = '00000000-0000-4000-8000-000000000178'
const publicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB'
for (const width of [1440, 390]) {
  test(`Linux support identity, policy and history at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 })
    await page.goto('/admin/login')
    await page.getByLabel('Имя пользователя').fill('console-e2e')
    await page.getByLabel('Пароль').fill('console-e2e-password')
    await page.getByRole('button', { name: 'Войти' }).click()
    await expect(page.getByRole('heading', { name: 'Состояние парка' })).toBeVisible()
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    await page.route('**/api/admin/console/session', route => route.fulfill({ json: { username: 'fixture-operator', scopes: ['updates:write'], csrf_token: 'fixture-only' } }))
    await page.route(`**/api/admin/console/devices/${deviceId}?*`, route => route.fulfill({ json: {
      device: { id: deviceId, device_identifier: 'ALT fixture', display_name: 'ALT Linux canary', online: false, os_name: 'ALT Linux', installation_state: 'installed' }, snapshots: [], capabilities: [],
    } }))
    await page.route(`**/api/admin/console/devices/${deviceId}/activity`, route => route.fulfill({ json: { data: { last_observed_at: null } } }))
    await page.route(`**/api/admin/console/devices/${deviceId}/power?*`, route => route.fulfill({ json: { summary: null, data: [], total: 0, limit: 20, offset: 0, has_more: false } }))
    let enabled = false
    await page.route(`**/api/admin/support-access/devices/${deviceId}/platform`, route => route.fulfill({ json: { device_id: deviceId, platform: 'linux_amd64' } }))
    const policy = () => ({ platform: 'linux_amd64', device_id: deviceId, revision: 1, enabled,
      expires_at: enabled ? '2030-01-01T00:00:00Z' : null, operator_public_keys: enabled ? [publicKey] : [],
      linux_admin_username: enabled ? 'root' : null, linux_admin_uid: enabled ? 0 : null,
      gateway_host: 'endpoint-staging.sosnadmin.local', gateway_port: 2222, tunnel_user: 'fixture-device', remote_port: 32001 })
    await page.route(`**/api/admin/support-access/linux/devices/${deviceId}`, route => route.fulfill({ json: {
      policy: policy(), configured_policy: { enabled: true, expires_at: '2030-01-01T00:00:00Z', operator_public_keys: [publicKey], linux_admin_username: 'root', linux_admin_uid: 0 },
      installed: true, component_version: '1.0.0', tunnel_connected: true, reported_at: new Date().toISOString(), host_public_key: publicKey,
      access_verified_at: null, reset_registration_allowed: false,
    } }))
    await page.route(`**/api/admin/support-access/linux/devices/${deviceId}/policy`, async route => {
      expect(route.request().postDataJSON()).toMatchObject({ platform: 'linux_amd64', linux_admin_username: 'root', linux_admin_uid: 0 })
      expect(route.request().postDataJSON()).not.toHaveProperty('windows_admin_username')
      enabled = route.request().postDataJSON().enabled
      await route.fulfill({ json: policy() })
    })
    await page.route(`**/api/admin/console/devices/${deviceId}/installation-events?*`, route => route.fulfill({ json: {
      installation: { state: 'removed', previous_device_id: 'old-device' }, has_more: false, data: [{ event: {
        schema_version: 'endpoint_linux_installation_event_v1', event_id: 'remove', action: 'removed', occurred_at: '2026-11-07T00:00:00Z',
        native: { version: '3.2.178', exit_code: 0, core_nevra: 'endpoint-agent-3.2.178-alt6.x86_64' }, cleanup: { support: 'incomplete', browser: 'external_preserved' },
      }, acknowledgement: { received_at: '2026-11-07T00:01:00Z' } }],
    } }))
    await page.goto(`/admin/devices/${deviceId}`)
    await expect(page.getByRole('heading', { name: 'ALT Linux canary' })).toBeVisible()
    await page.getByRole('button', { name: 'Доступ поддержки', exact: true }).click()
    await expect(page.getByLabel('UID администратора Linux')).toHaveValue('0')
    if (width === 390) {
      const form = await page.locator('.form-grid').boundingBox()
      const account = await page.getByLabel('Существующий администратор Linux').boundingBox()
      expect(account!.width).toBeGreaterThan(form!.width * 0.9)
    }
    await expect(page.getByText('Выключена', { exact: true })).toBeVisible()
    await expect(page.getByText('Оператор не подтвердил SSH-доступ')).toBeVisible()
    await page.getByLabel('Причина изменения доступа').fill('Explicit fixture enable')
    await page.getByLabel('UID администратора Linux').fill('1.5')
    await page.getByRole('button', { name: 'Включить доступ', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText('целый UID')
    await page.getByLabel('UID администратора Linux').fill('0')
    await page.getByRole('button', { name: 'Включить доступ', exact: true }).click()
    await expect(page.getByText('Включена', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Обновить доступ', exact: true }).click()
    await expect(page.getByLabel('UID администратора Linux')).toHaveValue('0')
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await page.screenshot({ path: testInfo.outputPath(`linux-support-${width}.png`), fullPage: true })
    await page.getByRole('button', { name: 'Установка', exact: true }).click()
    await expect(page.getByText('Удалён · 3.2.178')).toBeVisible()
    await expect(page.getByText(/Неизвестный результат native/)).toBeVisible()
    await expect(page.getByRole('link', { name: 'открыть сохранённую карточку' })).toHaveAttribute('href', '/admin/devices/old-device')
    expect(errors).toEqual([])
  })
}
