import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { InstallationHistory, installationLabel } from './InstallationHistory'
import { request } from './api'
vi.mock('./api', () => ({ request: vi.fn() }))
afterEach(() => { cleanup(); vi.resetAllMocks() })
it('distinguishes removed from offline and legacy uncertainty', () => {
  expect(installationLabel('removed', true)).toBe('Удалён')
  expect(installationLabel('installed', false)).toBe('Установлен · не в сети')
  expect(installationLabel('unknown', true)).toContain('Установка не подтверждена')
})
it('shows accepted native and independent cleanup facts', async () => {
  vi.mocked(request).mockResolvedValue({ installation: { state: 'removed' }, data: [{ event: { event_id: 'one', action: 'removed', occurred_at: '2026-11-07T00:00:00Z', native: { version: '3.2.177', exit_code: 0 }, cleanup: { support: 'incomplete', browser: 'external_preserved' } }, acknowledgement: { received_at: '2026-11-07T00:01:00Z' } }], has_more: false })
  render(<InstallationHistory deviceId="one" />)
  expect(await screen.findByText(/Удалён · 3.2.177/)).toBeTruthy()
  expect(screen.getByText(/Поддержка: Не завершено/)).toBeTruthy()
  expect(screen.getByText(/Браузеры: Внешние настройки сохранены/)).toBeTruthy()
})
