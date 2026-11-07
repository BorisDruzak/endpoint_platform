import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { InstallationHistory, installationLabel } from './InstallationHistory'
import { request } from './api'
import { MemoryRouter } from 'react-router'
vi.mock('./api', () => ({ request: vi.fn() }))
afterEach(() => { cleanup(); vi.resetAllMocks() })
it('distinguishes removed from offline and legacy uncertainty', () => {
  expect(installationLabel('removed', true)).toBe('Удалён')
  expect(installationLabel('installed', false)).toBe('Установлен · не в сети')
  expect(installationLabel('unknown', true)).toContain('Установка не подтверждена')
})

it('shows Linux native zero separately from pending delivery and history-only parent relation', async () => {
  vi.mocked(request).mockResolvedValue({ installation: { state: 'removed', previous_device_id: 'old-device' }, data: [{ event: {
    schema_version: 'endpoint_linux_installation_event_v1', event_id: 'linux-remove', action: 'removed', occurred_at: '2026-11-07T00:00:00Z',
    native: { version: '3.2.178', exit_code: 0, core_nevra: 'endpoint-agent-3.2.178-alt6.x86_64' },
    cleanup: { support: 'incomplete', browser: 'external_preserved' } }, acknowledgement: { received_at: '2026-11-07T00:01:00Z' } }], has_more: false })
  render(<MemoryRouter><InstallationHistory deviceId="linux" /></MemoryRouter>)
  expect(await screen.findByText(/endpoint-agent-3.2.178-alt6.x86_64/)).toBeTruthy()
  expect(screen.getByText(/только связь истории/)).toBeTruthy()
  expect(screen.getByText(/Неизвестный результат native/)).toBeTruthy()
  expect(screen.getByRole('link', { name: 'открыть сохранённую карточку' }).getAttribute('href')).toBe('/admin/devices/old-device')
})
it('shows accepted native and independent cleanup facts', async () => {
  vi.mocked(request).mockResolvedValue({ installation: { state: 'removed' }, data: [{ event: { event_id: 'one', action: 'removed', occurred_at: '2026-11-07T00:00:00Z', native: { version: '3.2.177', exit_code: 0 }, cleanup: { support: 'incomplete', browser: 'external_preserved' } }, acknowledgement: { received_at: '2026-11-07T00:01:00Z' } }], has_more: false })
  render(<InstallationHistory deviceId="one" />)
  expect(await screen.findByText(/Удалён · 3.2.177/)).toBeTruthy()
  expect(screen.getByText(/Поддержка: Не завершено/)).toBeTruthy()
  expect(screen.getByText(/Браузеры: Внешние настройки сохранены/)).toBeTruthy()
})
