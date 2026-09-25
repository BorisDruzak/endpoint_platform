import { cleanup, render, screen, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { DevicePolicyStatus } from './PolicyStatus'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const fact = (browser_family: 'chrome' | 'yandex', overrides: Record<string, unknown> = {}) => ({
  browser_family, browser_state: 'DETECTED', running_state: 'RUNNING', policy_owner: 'ENDPOINT',
  installation_policy_state: 'APPLIED', native_host_state: 'READY',
  effective_policy_state: 'APPLIED',
  extension_install_type: 'ADMIN',
  extension_version: '0.1.0', extension_last_seen_at: '2026-09-25T12:00:00Z',
  last_running_at: '2026-09-25T12:00:00Z', compliance_state: 'ACTIVE', reason: null,
  ...overrides,
})
const status = (overrides: Record<string, unknown> = {}) => ({
  policy_id: 'policy-1', policy_version: 1, policy_version_id: 'version-1',
  browser_required: true, deployment_mode: 'agent_managed', delivery_status: 'APPLIED',
  acknowledged_at: '2026-09-25T11:59:00Z', compliance: 'COMPLIANT',
  activity_sensor: 'ACTIVE', browser_sensor: 'ACTIVE', dlp_sensor: 'ACTIVE',
  browser_compliance: 'COMPLIANT',
  observed_at: '2026-09-25T12:00:00Z', browsers: [fact('chrome'), fact('yandex')],
  ...overrides,
})

it('shows server-derived overall and individual sensor status separately', async () => {
  const payload = status({
    compliance: 'PARTIAL', activity_sensor: 'STALE', browser_sensor: 'ACTIVE',
    dlp_sensor: 'UNAVAILABLE', browser_compliance: 'COMPLIANT',
  })
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ data: payload }) })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  const summary = (await screen.findByRole('heading', { name: 'Политика и датчики' })).closest('section')!
  expect(within(summary).getByText('Общее соответствие').closest('div')?.textContent).toContain('Частично соответствует')
  expect(within(summary).getByText('Датчик активности').closest('div')?.textContent).toContain('Данные устарели')
  expect(within(summary).getByText('Browser Sensor').closest('div')?.textContent).toContain('Активен')
  expect(within(summary).getByText('DLP').closest('div')?.textContent).toContain('Недоступен')
  expect(within(summary).getByText('Соответствие браузеров').closest('div')?.textContent).toContain('Соответствует')
})

it('shows separate managed and external browser facts without raw status codes', async () => {
  const payload = status({
    deployment_mode: 'external_managed', browser_compliance: 'PARTIAL',
    browsers: [
      fact('chrome', { policy_owner: 'EXTERNAL', running_state: 'CLOSED',
        effective_policy_state: 'UNKNOWN', compliance_state: 'STALE', reason: 'BROWSER_CLOSED' }),
      fact('yandex', { policy_owner: 'EXTERNAL', extension_version: null,
        extension_last_seen_at: null, effective_policy_state: 'UNKNOWN', compliance_state: 'NEVER_SEEN',
        reason: 'EXTENSION_NEVER_SEEN', running_state: 'CLOSED', last_running_at: null }),
    ],
  })
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ data: payload }) })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  const chrome = (await screen.findByRole('heading', { name: 'Chrome' })).closest('section')!
  const yandex = screen.getByRole('heading', { name: 'Яндекс Браузер' }).closest('section')!
  expect(within(chrome).getByText('Связь устарела')).toBeTruthy()
  expect(within(chrome).getByText(/Браузер сейчас закрыт/)).toBeTruthy()
  expect(within(chrome).getByText('0.1.0')).toBeTruthy()
  expect(within(yandex).getByText(/Расширение ещё не выходило на связь/)).toBeTruthy()
  expect(within(yandex).getByText('Ещё не обнаружено')).toBeTruthy()
  expect(screen.getAllByText('Внешняя политика').length).toBeGreaterThan(0)
  expect(screen.queryByText('BROWSER_CLOSED')).toBeNull()
})

it('does not present an unsupported agent as active', async () => {
  const payload = status({
    browser_compliance: 'UNSUPPORTED',
    browsers: [fact('chrome', { browser_state: null, running_state: null,
      policy_owner: null, installation_policy_state: null, native_host_state: null,
      effective_policy_state: 'UNKNOWN',
      extension_version: null, extension_last_seen_at: null, last_running_at: null,
      compliance_state: 'UNKNOWN', reason: 'AGENT_UNSUPPORTED' }),
    fact('yandex', { browser_state: null, running_state: null,
      policy_owner: null, installation_policy_state: null, native_host_state: null,
      effective_policy_state: 'UNKNOWN',
      extension_version: null, extension_last_seen_at: null, last_running_at: null,
      compliance_state: 'UNKNOWN', reason: 'AGENT_UNSUPPORTED' })],
  })
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ data: payload }) })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  expect(await screen.findByText('Не поддерживается агентом')).toBeTruthy()
  expect(screen.getAllByText('Нет подтверждения')).toHaveLength(4)
  expect(screen.queryByText('Активно')).toBeNull()
})

it('does not present a configured registry policy as browser-effective', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200,
    json: async () => ({ data: status({ browsers: [
      fact('chrome', { extension_install_type: 'UNKNOWN', effective_policy_state: 'UNKNOWN', compliance_state: 'UNKNOWN' }),
      fact('yandex', { extension_install_type: 'UNKNOWN', effective_policy_state: 'UNKNOWN', compliance_state: 'UNKNOWN' }),
    ] }) }),
  })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  const chrome = (await screen.findByRole('heading', { name: 'Chrome' })).closest('section')!
  expect(within(chrome).getByText('Настроена на устройстве')).toBeTruthy()
  expect(within(chrome).getByText('Действие политики в браузере не подтверждено')).toBeTruthy()
  expect(within(chrome).queryByText('Применена')).toBeNull()
})

it('labels browser-confirmed administrative installation separately from the machine value', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200,
    json: async () => ({ data: status() }),
  })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  const chrome = (await screen.findByRole('heading', { name: 'Chrome' })).closest('section')!
  expect(within(chrome).getByText('Применена')).toBeTruthy()
  expect(within(chrome).getByText('Подтверждена браузером')).toBeTruthy()
  expect(within(chrome).queryByText('Действие политики в браузере не подтверждено')).toBeNull()
})

it('does not claim Endpoint policy applied when another owner installed the extension', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200,
    json: async () => ({ data: status({ browsers: [
      fact('chrome', { policy_owner: 'EXTERNAL', effective_policy_state: 'UNKNOWN', compliance_state: 'ERROR', reason: 'POLICY_OWNER_MISMATCH' }),
      fact('yandex'),
    ] }) }),
  })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  const chrome = (await screen.findByRole('heading', { name: 'Chrome' })).closest('section')!
  expect(within(chrome).getByText('Настроена на устройстве')).toBeTruthy()
  expect(within(chrome).queryByText('Применена')).toBeNull()
})
