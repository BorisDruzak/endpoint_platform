import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, expect, it, vi } from 'vitest'
import { SecurityPage } from './SecurityPage'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('shows only published Browser Sensor release metadata and deployment URLs', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.endsWith('/browser-sensor/release')) return { ok: true, status: 200,
      json: async () => ({
        extension_version: '0.1.0', extension_id: 'abcdefghijklmnopabcdefghijklmnop',
        protocol_version: 1, source_revision: 'a'.repeat(40),
        artifact_sha256: 'b'.repeat(64), minimum_agent_version: '3.2.70',
        built_at: '2026-09-25T12:00:00Z', published_at: '2026-09-25T13:00:00Z',
        update_url: '/api/v1/browser-sensor/update.xml',
        artifact_url: '/api/v1/browser-sensor/releases/0.1.0/sensor.crx',
        signing_private_key: 'MUST_NOT_LEAK',
      }),
    } as Response
    if (url.includes('/console/policies/assignments/default')) return { ok: true, status: 200,
      json: async () => ({ data: null }) } as Response
    if (url.includes('/console/policies?')) return { ok: true, status: 200,
      json: async () => ({ data: [], total: 0, limit: 50, offset: 0 }) } as Response
    if (url.includes('/security/events')) return { ok: true, status: 200,
      json: async () => ({ data: [], total: 0, limit: 50, offset: 0 }) } as Response
    throw new Error(`Unexpected route ${url}`)
  }))
  render(<MemoryRouter initialEntries={['/admin/security']}><SecurityPage /></MemoryRouter>)
  const release = (await screen.findByRole('heading', { name: 'Browser Sensor' })).closest('section')!
  expect(within(release).getByText('0.1.0')).toBeTruthy()
  expect(within(release).getByText('abcdefghijklmnopabcdefghijklmnop')).toBeTruthy()
  expect(within(release).getByText('b'.repeat(64))).toBeTruthy()
  expect(within(release).getByText('3.2.70')).toBeTruthy()
  expect(within(release).getByRole('link', { name: 'Манифест обновления' }).getAttribute('href'))
    .toBe('/api/v1/browser-sensor/update.xml')
  expect(release.textContent).not.toContain('MUST_NOT_LEAK')
})

it('shows a safe browser upload and filters the event list', async () => {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    calls.push(url)
    if (url.endsWith('/browser-sensor/release')) return { ok: false, status: 404 } as Response
    if (url.includes('/console/policies/assignments/default')) return { ok: true, status: 200,
      json: async () => ({ data: null }) } as Response
    if (url.includes('/console/policies?')) return { ok: true, status: 200,
      json: async () => ({ data: [], total: 0, limit: 50, offset: 0 }) } as Response
    if (url.endsWith('/event-1')) return { ok: true, status: 200, json: async () => ({ data: {
      id: 'event-1', device_id: 'device-1', device_name: 'Рабочая станция',
      event_type: 'BROWSER_UPLOAD', channel: 'BROWSER', severity: 'INFO',
      occurred_at: '2026-09-25T12:00:00Z', received_at: '2026-09-25T12:00:01Z',
      user_login: 'operator', policy_id: 'policy-1', policy_version: 2,
      domain: 'example.org', metadata_valid: true,
      safe_metadata: { domain: 'example.org', origin: 'https://example.org',
        browser_family: 'yandex', file_count: 2, total_bytes: 4096,
        mime_categories: ['document'] },
    } }) } as Response
    return { ok: true, status: 200, json: async () => ({
      data: [{ id: 'event-1', device_id: 'device-1', device_name: 'Рабочая станция',
        event_type: 'BROWSER_UPLOAD', channel: 'BROWSER', severity: 'INFO',
        occurred_at: '2026-09-25T12:00:00Z', received_at: '2026-09-25T12:00:01Z',
        user_login: 'operator', policy_id: 'policy-1', policy_version: 2,
        domain: 'example.org', metadata_valid: true }],
      total: 1, limit: 50, offset: 0,
    }) } as Response
  }))
  render(<MemoryRouter initialEntries={['/admin/security']}><SecurityPage /></MemoryRouter>)
  expect(await screen.findByRole('heading', { name: 'Активная политика' })).toBeTruthy()
  expect(await screen.findByText('Релиз Browser Sensor ещё не опубликован.')).toBeTruthy()
  const list = (await screen.findByRole('heading', { name: /^События$/ })).closest('section')!
  expect(within(list).getByText('Рабочая станция')).toBeTruthy()
  expect(within(list).getByText('example.org')).toBeTruthy()
  fireEvent.click(within(list).getByRole('button', { name: 'Детали' }))
  const detail = await screen.findByRole('region', { name: 'Детали события' })
  expect(within(detail).getByText('Яндекс Браузер')).toBeTruthy()
  expect(within(detail).getByText('Документ')).toBeTruthy()
  expect(within(detail).getByText('Аудит')).toBeTruthy()
  expect(screen.queryByText('page_body')).toBeNull()
  fireEvent.change(screen.getByLabelText('Канал'), { target: { value: 'BROWSER' } })
  expect(calls.some(url => url.includes('channel=BROWSER'))).toBe(true)
})

it('explains the disabled feature in Russian', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 404 } as Response)))
  render(<MemoryRouter initialEntries={['/admin/security']}><SecurityPage /></MemoryRouter>)
  expect((await screen.findByText(/Раздел «Политики и DLP» сейчас отключён/)).textContent).toContain('Раздел «Политики и DLP» сейчас отключён')
})
