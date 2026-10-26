import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { afterEach, expect, it, vi } from 'vitest'
import { DeviceDetailPage, DevicesPage } from './FleetPages'
import { PowerStatus } from './PowerStatus'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })
const event = { schema_version: 'power_event_v1', event_identifier: 'power-1', event_kind: 'OS_SHUTDOWN_STARTED',
  occurred_at: '2026-10-20T07:00:00Z', observed_at: '2026-10-24T07:00:00Z', boot_id: 'boot-1', source: 'synthetic',
  native_record_id: '1', evidence: 'transition', sleep_subtype: null }
const source = { schema_version: 'power_source_status_v1', source: 'synthetic', availability: 'READY',
  reported_at: '2026-10-24T08:00:00Z', coverage_started_at: '2026-10-01T00:00:00Z', loss_count: 2, reset_count: 1 }
const power = { online: true, status: 'online', last_seen_at: '2026-10-24T08:00:00Z', source_status: source,
  source_fresh: true, history_available_from: '2026-10-01T00:00:00Z', latest_event: event }
const device = { id: 'pc1', display_name: 'Synthetic PC', online: true, last_seen_at: power.last_seen_at,
  ram_bytes: null, last_activity_observed_at: '2026-10-24T07:55:00Z', power }
const response = (data: unknown) => ({ ok: true, status: 200, json: async () => data })

it.each([
  [true, 'online', 'READY', event, 'В сети', 'Последнее событие: завершение работы ОС'],
  [false, 'unknown', 'READY', null, 'Нет связи — причина неизвестна', 'Событий питания нет'],
  [false, 'sleep', 'READY', { ...event, event_kind: 'OS_SLEEP_STARTED' }, 'Нет связи — причина неизвестна', 'Последнее событие: переход в сон'],
  [false, 'shutdown', 'READY', event, 'Нет связи — причина неизвестна', 'Последнее событие: завершение работы ОС'],
  [false, 'unknown', 'UNAVAILABLE', event, 'Нет связи — причина неизвестна', 'Источник событий питания недоступен'],
  [false, 'unknown', 'UNSUPPORTED', null, 'Нет связи — причина неизвестна', 'Источник событий питания не поддерживается'],
])('keeps connectivity independent of %s/%s power evidence (%s)', async (online, status, availability, latest, connection, label) => {
  const fetch = vi.fn(async (_url: string) => response({ data: [{ ...device, online, power: { ...power, status, latest_event: latest,
    source_status: { ...source, availability } } }], total: 1, offset: 0, limit: 50 }))
  vi.stubGlobal('fetch', fetch)
  render(<MemoryRouter><DevicesPage /></MemoryRouter>)
  const row = (await screen.findByText('Synthetic PC')).closest('tr')!
  expect(within(row).getByText(connection)).toBeTruthy()
  expect(within(row).getByText(label)).toBeTruthy()
  expect(fetch.mock.calls[0][0]).toContain('include_power=true')
})

it('paginates delayed history without replacing current summary or last activity', async () => {
  let finishPage: (value: unknown) => void = () => {}
  const fetch = vi.fn(async (url: string) => {
    if (url.includes('/power?')) {
      if (url.includes('offset=20')) return new Promise(resolve => { finishPage = resolve })
      return response({ summary: power, data: [event], total: 21, limit: 20, offset: 0, has_more: true })
    }
    if (url.endsWith('/activity')) return response({ data: { last_observed_at: '2026-10-24T07:55:00Z' } })
    return response({ device, snapshots: [], capabilities: [] })
  })
  vi.stubGlobal('fetch', fetch)
  render(<MemoryRouter initialEntries={['/admin/devices/pc1']}><Routes><Route path='/admin/devices/:deviceId' element={<DeviceDetailPage />} /></Routes></MemoryRouter>)
  const panel = await screen.findByRole('region', { name: 'Питание и связь' })
  expect(await within(panel).findByText('В сети')).toBeTruthy()
  expect(within(panel).getByText('Последняя связь')).toBeTruthy()
  expect(within(panel).getByText('Последняя активность')).toBeTruthy()
  expect(within(panel).getByText(/Потеряно событий: 2/)).toBeTruthy()
  fireEvent.click(within(panel).getByRole('button', { name: 'Далее' }))
  expect(await within(panel).findByRole('status')).toBeTruthy()
  expect((within(panel).getByRole('button', { name: 'Далее' }) as HTMLButtonElement).disabled).toBe(true)
  finishPage(response({ summary: power, data: [{ ...event, event_identifier: 'older', event_kind: 'OS_SLEEP_STARTED' }], total: 21, limit: 20, offset: 20, has_more: false }))
  expect(await within(panel).findByText('Переход в сон')).toBeTruthy()
  expect(within(panel).getByText('В сети')).toBeTruthy()
  expect(within(panel).getByText('Последнее событие: завершение работы ОС')).toBeTruthy()
  expect(within(panel).getByText(/21–21 из 21/)).toBeTruthy()
  fireEvent.click(within(panel).getByRole('button', { name: 'Назад' }))
  expect(await within(panel).findByText('Завершение работы ОС')).toBeTruthy()
})

it('keeps missing coverage explicit and labels a request separately from a transition', () => {
  const view = render(<PowerStatus value={null} />)
  expect(screen.getByText('Состояние источника событий питания неизвестно')).toBeTruthy()
  view.rerender(<PowerStatus value={{ ...power, status: 'unknown', source_fresh: false,
    latest_event: { ...event, evidence: 'request' } } as import('./powerApi').PowerSummary} />)
  expect(screen.getByText('Последнее событие: запрос: завершение работы ОС')).toBeTruthy()
  expect(screen.getByText('Состояние источника устарело')).toBeTruthy()
})

it('distinguishes shutdown requests in the existing device event list', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.includes('/power?')) return response({ summary: power, data: [], total: 0, limit: 20, offset: 0, has_more: false })
    if (url.includes('/events?')) return response({ data: [{ event_id: 'request', event_kind: 'OS_SHUTDOWN_STARTED', profile: 'power_v1',
      summary_code: 'OS_SHUTDOWN_STARTED', occurred_at: event.occurred_at, safe_details: { event: { evidence: 'request' } } }], limit: 20, offset: 0, has_more: false })
    return response({ device, snapshots: [], capabilities: [] })
  }))
  render(<MemoryRouter initialEntries={['/admin/devices/pc1']}><Routes><Route path='/admin/devices/:deviceId' element={<DeviceDetailPage />} /></Routes></MemoryRouter>)
  fireEvent.click(await screen.findByRole('button', { name: 'Изменения' }))
  expect(await screen.findByText('Запрос: завершение работы ОС')).toBeTruthy()
})
