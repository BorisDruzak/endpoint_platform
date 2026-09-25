import { cleanup, render, screen, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { DevicePolicyStatus } from './PolicyStatus'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const fact = (browser_family: 'chrome' | 'yandex', overrides: Record<string, unknown> = {}) => ({
  browser_family, browser_state: 'DETECTED', running_state: 'RUNNING', policy_owner: 'ENDPOINT',
  installation_policy_state: 'APPLIED', native_host_state: 'READY',
  extension_install_type: 'ADMIN',
  extension_version: '0.1.0', extension_last_seen_at: '2026-09-25T12:00:00Z',
  last_running_at: '2026-09-25T12:00:00Z', compliance_state: 'ACTIVE', reason: null,
  ...overrides,
})
const status = (overrides: Record<string, unknown> = {}) => ({
  policy_id: 'policy-1', policy_version: 1, policy_version_id: 'version-1',
  browser_required: true, deployment_mode: 'agent_managed', delivery_status: 'APPLIED',
  acknowledged_at: '2026-09-25T11:59:00Z', browser_compliance: 'COMPLIANT',
  observed_at: '2026-09-25T12:00:00Z', browsers: [fact('chrome'), fact('yandex')],
  ...overrides,
})

it('shows separate managed and external browser facts without raw status codes', async () => {
  const payload = status({
    deployment_mode: 'external_managed', browser_compliance: 'PARTIAL',
    browsers: [
      fact('chrome', { policy_owner: 'EXTERNAL', running_state: 'CLOSED',
        compliance_state: 'STALE', reason: 'BROWSER_CLOSED' }),
      fact('yandex', { policy_owner: 'EXTERNAL', extension_version: null,
        extension_last_seen_at: null, compliance_state: 'NEVER_SEEN',
        reason: 'BROWSER_NOT_LAUNCHED', running_state: 'CLOSED', last_running_at: null }),
    ],
  })
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ data: payload }) })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  const chrome = (await screen.findByRole('heading', { name: 'Chrome' })).closest('section')!
  const yandex = screen.getByRole('heading', { name: 'Яндекс Браузер' }).closest('section')!
  expect(within(chrome).getByText('Связь устарела')).toBeTruthy()
  expect(within(chrome).getByText(/Браузер сейчас закрыт/)).toBeTruthy()
  expect(within(chrome).getByText('0.1.0')).toBeTruthy()
  expect(within(yandex).getByText(/Браузер не запускался после настройки политики/)).toBeTruthy()
  expect(within(yandex).getByText('Ещё не обнаружено')).toBeTruthy()
  expect(screen.getAllByText('Внешняя политика').length).toBeGreaterThan(0)
  expect(screen.queryByText('BROWSER_CLOSED')).toBeNull()
})

it('does not present an unsupported agent as active', async () => {
  const payload = status({
    browser_compliance: 'UNSUPPORTED',
    browsers: [fact('chrome', { browser_state: null, running_state: null,
      policy_owner: null, installation_policy_state: null, native_host_state: null,
      extension_version: null, extension_last_seen_at: null, last_running_at: null,
      compliance_state: 'UNKNOWN', reason: 'AGENT_UNSUPPORTED' }),
    fact('yandex', { browser_state: null, running_state: null,
      policy_owner: null, installation_policy_state: null, native_host_state: null,
      extension_version: null, extension_last_seen_at: null, last_running_at: null,
      compliance_state: 'UNKNOWN', reason: 'AGENT_UNSUPPORTED' })],
  })
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ data: payload }) })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  expect(await screen.findByText('Не поддерживается агентом')).toBeTruthy()
  expect(screen.getAllByText('Нет подтверждения')).toHaveLength(2)
  expect(screen.queryByText('Активно')).toBeNull()
})

it('does not present a configured registry policy as browser-effective', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200,
    json: async () => ({ data: status({ browsers: [
      fact('chrome', { extension_install_type: 'UNKNOWN', compliance_state: 'UNKNOWN' }),
      fact('yandex', { extension_install_type: 'UNKNOWN', compliance_state: 'UNKNOWN' }),
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
  expect(within(chrome).queryByText('Действие политики в браузере не подтверждено')).toBeNull()
})

it('does not claim Endpoint policy applied when another owner installed the extension', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200,
    json: async () => ({ data: status({ browsers: [
      fact('chrome', { policy_owner: 'EXTERNAL', compliance_state: 'ERROR', reason: 'POLICY_OWNER_MISMATCH' }),
      fact('yandex'),
    ] }) }),
  })))
  render(<DevicePolicyStatus deviceId="device-1" />)
  const chrome = (await screen.findByRole('heading', { name: 'Chrome' })).closest('section')!
  expect(within(chrome).getByText('Настроена на устройстве')).toBeTruthy()
  expect(within(chrome).queryByText('Применена')).toBeNull()
})
