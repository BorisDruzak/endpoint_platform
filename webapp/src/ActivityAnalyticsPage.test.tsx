import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router'
import { afterEach, expect, it, vi } from 'vitest'
import { ActivityAnalyticsPage } from './ActivityAnalyticsPage'

const metrics = { seconds: { ACTIVE: 60, IDLE: 15, LOCKED: 0, DISCONNECTED: 0, UNKNOWN: 30 }, observed_span_seconds: 105,
  coverage: 0.714, applications: [{ label: 'Microsoft Word', category: 'office', seconds: 60 }], categories: { office: 60 },
  overlap_seconds: 0, pending: false, updated_at: '2026-10-20T08:00:00Z' }
const employee = { user_key: 'domain\\alice', user_login: 'DOMAIN\\Alice', devices: [{ id: 'pc1', name: 'PC-1', online: true }],
  state: 'ACTIVE', fresh: true, last_observed_at: '2026-10-20T08:00:00Z', metrics, reason: null }
const meta = { today: '2026-10-20', since: '2026-10-19', until: '2026-10-20', timezone: 'Asia/Yekaterinburg', timezones: ['Asia/Yekaterinburg', 'UTC'],
  detail_available_from: '2026-10-07', aggregate_available_from: '2026-07-23', max_gap_seconds: 45,
  generated_at: '2026-10-20T08:00:00Z', collection_enabled: true }

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function setup(data = [employee]) {
  const fetch = vi.fn(async (path: string) => ({ ok: true, status: 200, json: async () => path.includes('/timeline?')
    ? { day: '2026-10-20', timezone: meta.timezone, started_at: '2026-10-19T19:00:00Z', ended_at: '2026-10-20T19:00:00Z',
      data: [{ started_at: '2026-10-20T08:00:00Z', ended_at: '2026-10-20T08:01:00Z', state: 'ACTIVE', seconds: 60,
        process_name: 'winword.exe', device_id: 'pc1', application_category: 'office', overlap: false, attributed: true },
      { started_at: '2026-10-20T08:01:00Z', ended_at: '2026-10-20T08:02:00Z', state: 'UNKNOWN', seconds: 60,
        process_name: null, device_id: null, application_category: null, overlap: false, attributed: false }],
      power_events: [{ device_id: 'pc1', event: { event_identifier: 'power-1', event_kind: 'OS_SLEEP_STARTED', evidence: 'transition', source: 'synthetic', occurred_at: '2026-10-20T08:01:00Z', observed_at: '2026-10-20T08:05:00Z' } }],
      power_events_truncated: true, connection_gaps: [{ device_id: 'pc1', started_at: '2026-10-20T08:01:00Z', ended_at: '2026-10-20T08:02:00Z' }], devices: employee.devices }
    : path.includes('/user?') ? { data: employee, daily: [{ day: '2026-10-19', metrics, timeline_available: true }, { day: '2026-10-20', metrics, timeline_available: true }], meta }
      : { data, total: data.length, offset: 0, limit: 50, summary: { fresh: 1, active: 1, idle: 0, locked_disconnected: 0, unknown: 0, unknown_devices: 0 }, meta },
  }))
  vi.stubGlobal('fetch', fetch)
  function Location() { return <output data-testid="location">{useLocation().search}</output> }
  render(<MemoryRouter initialEntries={['/admin/activity-analytics?period=today']}><ActivityAnalyticsPage /><Location /></MemoryRouter>)
  return fetch
}

it('keeps filters and selected employee in URL, opens applications and timeline, returns to table', async () => {
  const fetch = setup()
  await screen.findByRole('button', { name: 'DOMAIN\\Alice' })
  fireEvent.change(screen.getByLabelText('Период'), { target: { value: '7d' } })
  await waitFor(() => expect(screen.getByTestId('location').textContent).toContain('period=7d'))
  fireEvent.change(screen.getByLabelText('Поиск'), { target: { value: 'PC-1' } })
  fireEvent.click(await screen.findByRole('button', { name: 'DOMAIN\\Alice' }))
  expect(await screen.findByRole('heading', { name: 'Приложения' })).toBeTruthy()
  await screen.findByRole('button', { name: /ACTIVE.*winword.exe/ })
  fireEvent.click(screen.getByRole('button', { name: /ACTIVE.*winword.exe/ }))
  expect(screen.getByText(/winword.exe · PC-1/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: /2026-10-19 ACTIVE/ }))
  await waitFor(() => expect(screen.getByTestId('location').textContent).toContain('day=2026-10-19'))
  expect(await screen.findByRole('heading', { name: 'Приложения' })).toBeTruthy()
  await waitFor(() => expect(fetch.mock.calls.some(([path]) => path.includes('day=2026-10-19'))).toBe(true))
  fireEvent.click(screen.getByRole('button', { name: 'К таблице' }))
  expect(await screen.findByRole('columnheader', { name: 'Сотрудник' })).toBeTruthy()
  expect(screen.getByTestId('location').textContent).toContain('search=PC-1')
  expect(screen.getByTestId('location').textContent).not.toContain('user_key')
  expect(fetch.mock.calls.some(([path]) => path.includes('period=7d'))).toBe(true)
})

it('explains absent telemetry and does not display invented zero work time', async () => {
  setup([{ ...employee, user_key: null, user_login: null, state: 'UNKNOWN', fresh: false, last_observed_at: null,
    metrics: null, reason: 'Activity Sensor не передал данные' }] as unknown as typeof employee[])
  expect(await screen.findByText('Activity Sensor не передал данные')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'DOMAIN\\Alice' })).toBeNull()
})

it('opts into separate power markers and preserves UNKNOWN gaps and activity totals', async () => {
  const fetch = setup()
  fireEvent.click(await screen.findByRole('button', { name: 'DOMAIN\\Alice' }))
  expect(await screen.findByRole('heading', { name: 'События питания ОС' })).toBeTruthy()
  expect(screen.getByText('Переход в сон')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: /^UNKNOWN/ }))
  expect(screen.getAllByText('Нет достоверных данных')).toHaveLength(2)
  expect(screen.getByText(/Время не приписано сотруднику/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: /Событие питания: Переход в сон/ }))
  expect(screen.getByRole('region', { name: 'Выбранное событие питания' }).textContent).toContain('synthetic')
  expect(screen.getByText(/Время не приписано сотруднику/)).toBeTruthy()
  expect(screen.getByRole('heading', { name: 'Нет соединения WSS с устройством' })).toBeTruthy()
  expect(screen.getByText(/Показана часть событий питания/)).toBeTruthy()
  expect(fetch.mock.calls.some(([url]) => url.includes('/timeline?') && url.includes('include_power=true'))).toBe(true)
})

it('shows request errors with a working retry and empty results', async () => {
  const fetch = setup([])
  expect(await screen.findByText('За выбранный период записи не найдены.')).toBeTruthy()
  fetch.mockImplementationOnce(async () => { throw new Error('network') })
  fireEvent.click(screen.getByRole('button', { name: 'Обновить' }))
  expect(await screen.findByRole('alert')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Повторить' }))
  await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
})
