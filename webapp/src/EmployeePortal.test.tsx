import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, expect, it, vi } from 'vitest'
import { App } from './App'
import { WorkTimeRing } from './WorkTimeRing'
import type { EmployeeGrant } from './employeeApi'

const session = { person_id: 'person-a', department_id: 'department-a', csrf_token: 'employee-csrf', grants: [] }
const day = { person_id: 'person-a', day: '2026-10-27', timezone: 'Asia/Yekaterinburg', status: 'WORKING',
  work_intervals: [{ id: 'work-1', started_at: '2026-10-27T03:00:00Z', ended_at: '2026-10-27T04:00:00Z', status: 'WORKING', source: 'employee' }],
  activity_intervals: [{ started_at: '2026-10-27T03:00:00Z', ended_at: '2026-10-27T03:30:00Z', state: 'UNKNOWN', seconds: 1800, attributed: false }],
  totals: { work_seconds: 3600, break_seconds: 0, off_pc_seconds: 0, scheduled_seconds: 28800 }, coverage: { state: 'partial', measured_seconds: 0, unknown_seconds: 1800 },
  schedule: [], explanations: [], corrections: [], pending_explanations: [] }

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function setup(entry = '/employee?day=2026-10-27', grants: EmployeeGrant[] = session.grants) {
  const fetch = vi.fn(async (path: string, _init?: RequestInit): Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }> => ({ ok: true, status: 200, json: async () => path === '/api/employee/session' ? { ...session, grants }
    : path.includes('/categories') ? { categories: [{ code: 'meeting', label: 'Совещание', requires_comment: true }] }
      : path.includes('/history') ? { events: [], explanations: [], corrections: [], approvals: [] }
        : path.includes('/month') ? { month: '2026-10', days: [day], totals: day.totals }
          : path.includes('/pending') ? { requests: [] } : day }))
  vi.stubGlobal('fetch', fetch)
  render(<MemoryRouter initialEntries={[entry]}><App /></MemoryRouter>)
  return fetch
}

it('uses an employee SSO entry without an admin session or password form', () => {
  const fetch = setup('/employee/login')
  expect(screen.getByRole('heading', { name: 'Вход сотрудника' })).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Войти с доменной учётной записью' }).getAttribute('href')).toBe('/auth/employee/login')
  expect(screen.queryByLabelText('Пароль')).toBeNull()
  expect(fetch).not.toHaveBeenCalled()
})

it('keeps work and UNKNOWN evidence independent, selects a keyboard interval and sends scoped explanation', async () => {
  const fetch = setup()
  await screen.findByRole('heading', { name: 'Мой рабочий день' })
  expect(await screen.findByText('Подтверждено: 1 ч 00 мин')).toBeTruthy()
  const technical = await screen.findByRole('button', { name: /^Компьютер.*UNKNOWN.*08:00.*08:30/ })
  fireEvent.keyDown(technical, { key: 'Enter' })
  expect(await screen.findByRole('region', { name: 'Выбранный интервал' })).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Причина'), { target: { value: 'meeting' } })
  fireEvent.change(screen.getByLabelText('Комментарий'), { target: { value: 'Совещание отдела' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить объяснение' }))
  await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === '/api/employee/worktime/explanations')).toBe(true))
  const call = fetch.mock.calls.find(([path]) => path === '/api/employee/worktime/explanations') as unknown as [string, RequestInit]
  expect(new Headers(call[1].headers).get('X-CSRF-Token')).toBe('employee-csrf')
  expect(JSON.parse(call[1].body as string)).toMatchObject({ category_code: 'meeting', comment: 'Совещание отдела' })
  expect(call[1].body).not.toContain('person_id')
  expect(fetch.mock.calls.every(([path]) => !path.includes('/api/admin'))).toBe(true)
  expect(screen.queryByRole('link', { name: 'Подразделение' })).toBeNull()
  expect(screen.queryByRole('link', { name: 'DLP' })).toBeNull()
})

it('revalidates on focus and ignores a late response from the previous employee', async () => {
  const fetch = setup()
  await screen.findByText('Подтверждено: 1 ч 00 мин')
  let release: (value: { ok: boolean; status: number; json: () => Promise<unknown> }) => void = () => {}
  fetch.mockImplementationOnce(() => new Promise(resolve => { release = resolve }))
  fireEvent.click(screen.getByRole('button', { name: 'Обновить' }))
  fetch.mockImplementation(async (path: string) => ({ ok: true, status: 200, json: async () => path === '/api/employee/session'
    ? { ...session, person_id: 'person-b', csrf_token: 'new-csrf' }
    : path.includes('/categories') ? { categories: [] } : path.includes('/history') ? { events: [], explanations: [], corrections: [], approvals: [] }
      : { ...day, person_id: 'person-b', totals: { ...day.totals, work_seconds: 7200 } } }))
  fireEvent(window, new Event('focus'))
  expect(await screen.findByText('Подтверждено: 2 ч 00 мин')).toBeTruthy()
  release({ ok: true, status: 200, json: async () => day })
  await waitFor(() => expect(screen.queryByText('Подтверждено: 1 ч 00 мин')).toBeNull())
})

it('hides role routes and refuses a direct manager URL without that grant', async () => {
  const fetch = setup('/employee/manager')
  expect(await screen.findByRole('heading', { name: 'Доступ ограничен' })).toBeTruthy()
  expect(fetch.mock.calls).toHaveLength(1)
  expect(screen.queryByRole('link', { name: 'Табели и отчёты' })).toBeNull()
})

it('places midnight at the top and clips cross-midnight technical arcs proportionally', () => {
  const interval = { started_at: '2026-10-26T18:30:00Z', ended_at: '2026-10-26T20:00:00Z', state: 'UNKNOWN', seconds: 5400, attributed: false }
  const { container } = render(<WorkTimeRing day={{ ...day, activity_intervals: [interval], work_intervals: [] }} onSelect={() => {}} />)
  const arc = container.querySelector('circle[role=button]')!
  expect(arc.getAttribute('transform')).toBe('rotate(-90 180 180)')
  expect(Number(arc.getAttribute('stroke-dashoffset'))).toBe(0)
  expect(Number(arc.getAttribute('stroke-dasharray')!.split(' ')[0])).toBeCloseTo(2 * Math.PI * 112 / 24)
})

it('does not grant a technical administrator implicit DLP access', async () => {
  const fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ username: 'technical-admin', scopes: [], csrf_token: 'admin-csrf' }) }))
  vi.stubGlobal('fetch', fetch)
  render(<MemoryRouter initialEntries={['/admin/security']}><App /></MemoryRouter>)
  expect(await screen.findByRole('heading', { name: 'Доступ к DLP ограничен' })).toBeTruthy()
  expect(screen.queryByRole('link', { name: 'Политики и DLP' })).toBeNull()
  expect(fetch.mock.calls).toHaveLength(1)
})

it('reuses the same idempotency key after a failed explanation request', async () => {
  const fetch = setup()
  fireEvent.click(await screen.findByRole('button', { name: /^Текст: Компьютер.*UNKNOWN/ }))
  fireEvent.change(screen.getByLabelText('Причина'), { target: { value: 'meeting' } })
  fireEvent.change(screen.getByLabelText('Комментарий'), { target: { value: 'Совещание' } })
  fetch.mockImplementationOnce(async () => { throw new Error('offline') })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить объяснение' }))
  expect(await screen.findByRole('alert')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить объяснение' }))
  await waitFor(() => expect(fetch.mock.calls.filter(([path]) => path.endsWith('/explanations'))).toHaveLength(2))
  const writes = fetch.mock.calls.filter(([path]) => path.endsWith('/explanations'))
  expect(JSON.parse(writes[0][1]!.body as string).idempotency_key).toBe(JSON.parse(writes[1][1]!.body as string).idempotency_key)
})

it('splits outer work arcs for unexplained and explained intervals without adding work time', () => {
  const pending = { id: 'pending', started_at: '2026-10-27T03:10:00Z', ended_at: '2026-10-27T03:40:00Z', state: 'pending' }
  const explanation = { id: 'explained', started_at: '2026-10-27T03:20:00Z', ended_at: '2026-10-27T03:30:00Z', category_code: 'meeting', comment: 'Совещание отдела' }
  render(<WorkTimeRing day={{ ...day, explanations: [explanation], pending_explanations: [pending] }} categories={[{ code: 'meeting', label: 'Совещание', requires_comment: false }]} onSelect={() => {}} />)
  expect(screen.getByRole('button', { name: /^Рабочий статус.*08:10–08:20.*Требует объяснения/ })).toBeTruthy()
  expect(screen.getByRole('button', { name: /^Рабочий статус.*08:20–08:30.*Объяснение: Совещание/ })).toBeTruthy()
  expect(screen.getByText('1 ч 00 мин')).toBeTruthy()
})

it('opens an owned pending request from the companion deep link', async () => {
  const requestId = '00000000-0000-4000-8000-000000000002'
  const fetch = setup(`/employee?day=2026-10-27&request_id=${requestId}`)
  fetch.mockImplementation(async (path: string) => ({ ok: true, status: 200, json: async () => path.includes('/categories') ? { categories: [] }
    : path.includes('/history') ? { events: [], explanations: [], corrections: [], approvals: [] }
      : { ...day, pending_explanations: [{ id: requestId, started_at: '2026-10-27T03:00:00Z', ended_at: '2026-10-27T03:30:00Z', state: 'pending' }] } }))
  expect(await screen.findByRole('region', { name: 'Выбранный интервал' })).toBeTruthy()
  expect(screen.getByRole('heading', { name: 'Требует объяснения' })).toBeTruthy()
  expect(fetch.mock.calls.every(([path]) => !path.includes('person_id='))).toBe(true)
})

it('does not resolve or display a foreign request from a deep link', async () => {
  const fetch = setup('/employee?day=2026-10-27&request_id=00000000-0000-4000-8000-000000000003')
  expect(await screen.findByText('Запрос уже объяснён или недоступен в вашем рабочем дне.')).toBeTruthy()
  expect(screen.queryByRole('region', { name: 'Выбранный интервал' })).toBeNull()
  expect(fetch.mock.calls.every(([path]) => !path.includes('00000000-0000-4000-8000-000000000003'))).toBe(true)
})

it('gives a pure HR account its approval entry without loading a department roster', async () => {
  const fetch = setup('/employee/approvals', [{ role: 'hr', department_id: 'department-a' }])
  fetch.mockImplementation(async (path: string) => ({ ok: true, status: 200, json: async () => path === '/api/employee/session' ? { ...session, grants: [{ role: 'hr', department_id: 'department-a' }] } : { corrections: [{ id: 'review-1', person_id: 'person-b', started_at: '2026-10-27T03:00:00Z', ended_at: '2026-10-27T04:00:00Z', status: 'OFF_PC', reason: 'Подтверждённая служебная работа', decision: 'pending' }] } }))
  expect(await screen.findByRole('heading', { name: 'Согласования корректировок' })).toBeTruthy()
  fireEvent.click(await screen.findByRole('button', { name: 'Согласовать' }))
  await waitFor(() => expect(fetch.mock.calls.some(([path]) => path.endsWith('/review-1/decision'))).toBe(true))
  expect(screen.getByRole('link', { name: 'Согласования' })).toBeTruthy()
  expect(fetch.mock.calls.every(([path]) => !path.endsWith('/people'))).toBe(true)
})

it('fails closed on a revoked session and clears personnel content', async () => {
  const fetch = setup()
  await screen.findByText('Подтверждено: 1 ч 00 мин')
  fetch.mockImplementationOnce(async () => ({ ok: false, status: 401, json: async () => ({}) }))
  fireEvent.click(screen.getByRole('button', { name: 'Обновить' }))
  expect(await screen.findByRole('heading', { name: 'Вход сотрудника' })).toBeTruthy()
  expect(screen.queryByText('Подтверждено: 1 ч 00 мин')).toBeNull()
})
