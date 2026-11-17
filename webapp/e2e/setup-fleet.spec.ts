import { expect, test } from '@playwright/test'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Browser state is an explicit HTTP fixture; production persistence, authority
// and scheduler races are exercised separately on isolated PostgreSQL.
for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
  test(`full Setup policy preview, wave, enable, reload and pause at ${viewport.width}px`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    await page.setViewportSize(viewport)
    await page.goto('/admin/login')
    await page.getByLabel('Имя пользователя').fill('console-e2e')
    await page.getByLabel('Пароль').fill('console-e2e-password')
    await page.getByRole('button', { name: 'Войти' }).click()
    await expect(page.getByRole('heading', { name: 'Состояние парка' })).toBeVisible()
    const release = { id: 'release158', version: '3.2.158', artifact_name: 'EndpointAgentSetup-3.2.158-r3-x64.exe' }
    const devices = [{ id: 'source156', display_name: 'Windows Foundation156' }, { id: 'current158', display_name: 'Windows Foundation158' }]
    let policy = { revision: 0, enabled: false, release_id: null as string | null, scope: 'all_active', device_ids: [] as string[], max_parallel: 1, reason: '', safe_code: null }
    let writes = 0
    await page.route('**/api/admin/setup-updates/releases', route => route.fulfill({ json: { data: [release] } }))
    await page.route('**/api/admin/console/devices?*', route => route.fulfill({ json: { data: devices, total: 2 } }))
    await page.route('**/api/admin/setup-updates/fleet', async route => {
      if (route.request().method() === 'PUT') {
        const body = route.request().postDataJSON()
        expect(body.expected_revision).toBe(policy.revision)
        expect(route.request().headers()['x-csrf-token']).toBeTruthy()
        policy = { ...policy, ...body, revision: policy.revision + 1 }; writes++
        await route.fulfill({ json: { data: policy } }); return
      }
      await route.fulfill({ json: { data: policy, qualifications: { release158: [{ source_foundation: '3.2.156', expires_at: '2026-12-01' }] }, active_chains: 0, decisions: [{ device_id: 'other', display_name: 'Ожидающий компьютер', status: 'waiting', safe_code: 'waiting_reconnect', policy_revision: 1 }] } })
    })
    await page.route('**/api/admin/setup-updates/fleet/preview', route => route.fulfill({ json: { read_only: true, counts: { eligible: 1, already_current: 1 }, active_chains: 0, available_slots: 1, evaluated_count: 2, truncated: false, data: [{ device_id: 'source156', display_name: 'Windows Foundation156', status: 'eligible', safe_code: 'eligible' }, { device_id: 'current158', display_name: 'Windows Foundation158', status: 'already_current', safe_code: 'already_current' }] } }))
    await page.goto('/admin/updates?lane=setup')
    const section = page.getByRole('region', { name: 'Автообновление Windows', exact: true })
    await expect(section.getByText(/Версия политики: 0/)).toBeVisible()
    await section.getByLabel('Целевой полный Setup').selectOption('release158')
    await section.getByLabel('Причина политики').fill('Explicit isolated wave')
    await section.getByLabel('Охват обновления').selectOption('selected')
    await section.getByLabel('Windows Foundation156', { exact: true }).check()
    await section.getByRole('button', { name: 'Предпросмотр охвата' }).click()
    await expect(section.getByText(/Готовы: 1/)).toBeVisible()
    expect(writes).toBe(0)
    await section.getByLabel('Включить автоматическое обновление').check()
    await section.getByLabel('Одновременных цепочек').selectOption('2')
    await section.getByRole('button', { name: 'Сохранить политику' }).click()
    await expect(section.getByText(/Политика сохранена. Новые цепочки/)).toBeVisible()
    expect(policy.device_ids).toEqual(['source156'])
    expect(policy.max_parallel).toBe(2)
    await page.reload()
    await expect(section.getByLabel('Включить автоматическое обновление')).toBeChecked()
    await expect(section.getByLabel('Одновременных цепочек')).toHaveValue('2')
    await expect(section.getByLabel('Windows Foundation156', { exact: true })).toBeChecked()
    await expect(section.getByText('Ожидается свежее подключение WSS')).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await page.screenshot({ path: join(tmpdir(), `endpoint-setup-fleet-${viewport.width}.png`), fullPage: true })
    await section.getByLabel('Включить автоматическое обновление').uncheck()
    await section.getByRole('button', { name: 'Сохранить политику' }).click()
    await expect(section.getByText(/Политика сохранена на паузе/)).toBeVisible()
    expect(policy.enabled).toBe(false)
    expect(errors).toEqual([])
  })
}
