import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, expect, it, vi } from 'vitest'
import { PolicyFleet } from './PolicyFleet'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const row = (id: string, compliance: string) => ({
  id, device_identifier: `FLEET-${id}`, display_name: `Устройство ${id}`,
  agent_version: '3.2.70', online: true, policy_name: 'Основная', policy_version: 3,
  applied_version: 2, delivery_status: 'STALE', compliance,
  acknowledged_at: '2026-09-25T12:00:00Z', activity_sensor: 'STALE',
  browser_sensor: 'UNKNOWN', dlp_sensor: 'UNAVAILABLE',
})

it('renders safe fleet facts and filters before pagination', async () => {
  const paths: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    paths.push(path)
    const selected = path.includes('compliance=PARTIAL')
    const second = path.includes('offset=50')
    return { ok: true, status: 200, json: async () => ({
      data: [row(second ? '52' : selected ? '02' : '01', selected ? 'PARTIAL' : 'STALE')],
      total: selected ? 51 : 1, limit: 50, offset: second ? 50 : 0,
    }) }
  }))
  render(<MemoryRouter><PolicyFleet /></MemoryRouter>)
  const table = (await screen.findByRole('heading', { name: 'Состояние политики по устройствам' })).closest('section')!
  expect(await within(table).findByText('Устройство 01')).toBeTruthy()
  expect(within(table).getAllByText('Данные устарели').length).toBeGreaterThan(1)
  expect(within(table).getByText('Нет подтверждения')).toBeTruthy()
  expect(within(table).getByText('Недоступен')).toBeTruthy()
  expect(within(table).getByRole('link', { name: 'Открыть' }).getAttribute('href')).toBe('/admin/devices/01')
  fireEvent.change(within(table).getByLabelText('Соответствие'), { target: { value: 'PARTIAL' } })
  expect(await within(table).findByText('Устройство 02')).toBeTruthy()
  expect(within(table).getAllByText('Частично соответствует')).toHaveLength(2)
  expect(paths.some(path => path.includes('compliance=PARTIAL') && path.includes('offset=0'))).toBe(true)
  fireEvent.click(within(table).getByRole('button', { name: 'Далее' }))
  expect(await within(table).findByText('Устройство 52')).toBeTruthy()
  expect(paths.some(path => path.includes('compliance=PARTIAL') && path.includes('offset=50'))).toBe(true)
})

it('shows an empty filtered state and supports retry after a read error', async () => {
  let attempts = 0
  vi.stubGlobal('fetch', vi.fn(async () => {
    attempts += 1
    if (attempts === 1) throw new Error('network')
    return { ok: true, status: 200, json: async () => ({ data: [], total: 0, limit: 50, offset: 0 }) }
  }))
  render(<MemoryRouter><PolicyFleet /></MemoryRouter>)
  expect(await screen.findByRole('alert')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Повторить' }))
  expect(await screen.findByText('Устройства по заданным условиям не найдены.')).toBeTruthy()
})
