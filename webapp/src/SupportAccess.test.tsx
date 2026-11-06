import { cleanup, fireEvent, render, screen, waitFor, act } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { SupportAccess } from './SupportAccess'
import { request, ApiError } from './api'
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }))
afterEach(() => { cleanup(); vi.clearAllMocks() })

const publicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB'
const status = (device = 'one') => ({ policy: { device_id: device, revision: 1, enabled: false, expires_at: null,
  gateway_host: 'endpoint.sosnadmin.local', gateway_port: 2222, gateway_host_public_key: publicKey,
  tunnel_user: 'eps-device', remote_port: 32000, local_port: 22222, operator_public_keys: [], windows_admin_username: null },
  component_version: '1.0.0', installed: true, tunnel_connected: true, reported_at: new Date().toISOString(),
  last_error_code: null, host_public_key: publicKey, access_verified_at: null, access_verified_by: null,
  verification_kind: 'operator_attestation', revoked_at: null, reset_registration_allowed: false })

it('keeps installed, policy, tunnel and operator SSH proof separate', async () => {
  vi.mocked(request).mockResolvedValue(status())
  render(<SupportAccess deviceId="one" canWrite={false} />)
  expect(await screen.findByText('Установлен · 1.0.0')).toBeTruthy()
  expect(screen.getByText('Выключена')).toBeTruthy()
  expect(screen.getByText('Подключён по отчёту компонента')).toBeTruthy()
  expect(screen.getByText('Оператор не подтвердил SSH-доступ')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Включить доступ' })).toBeNull()
})

it('marks old reports stale and preserves historical attestation wording', async () => {
  vi.mocked(request).mockResolvedValue({ ...status(), reported_at: '2000-01-01T00:00:00Z', access_verified_at: '2000-01-01T00:00:00Z', access_verified_by: 'operator' })
  render(<SupportAccess deviceId="one" canWrite={false} />)
  expect(await screen.findByText(/Отчёт устарел/)).toBeTruthy()
  expect(screen.getByText('Текущее подключение не подтверждено')).toBeTruthy()
  expect(screen.getByText(/Историческое подтверждение оператора/)).toBeTruthy()
})

it('never applies an old device response to a new device', async () => {
  let resolveOld!: (value: unknown) => void
  vi.mocked(request).mockImplementation(path => path.endsWith('/one') ? new Promise(resolve => { resolveOld = resolve }) : Promise.resolve(status('two')))
  const { rerender } = render(<SupportAccess deviceId="one" canWrite={false} />)
  rerender(<SupportAccess deviceId="two" canWrite={false} />)
  await screen.findByText('Установлен · 1.0.0')
  await act(async () => resolveOld({ ...status(), component_version: '9.9.9' }))
  expect(screen.queryByText('Установлен · 9.9.9')).toBeNull()
})

it('saves explicit operator keys, existing username and bounded expiry, then refreshes', async () => {
  vi.mocked(request).mockResolvedValue(status())
  render(<SupportAccess deviceId="one" canWrite />)
  await screen.findByText('Установлен · 1.0.0')
  fireEvent.change(screen.getByLabelText('Публичные ключи операторов'), { target: { value: publicKey } })
  fireEvent.change(screen.getByLabelText('Причина изменения доступа'), { target: { value: 'Pilot acceptance' } })
  fireEvent.click(screen.getByRole('button', { name: 'Включить доступ' }))
  await waitFor(() => expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/support-access/devices/one/policy', expect.objectContaining({ method: 'PUT' })))
  const mutation = vi.mocked(request).mock.calls.find(([, init]) => init?.method === 'PUT')!
  const body = JSON.parse(String(mutation[1]?.body))
  expect(body.windows_admin_username).toBe('admin-2')
  expect(body.operator_public_keys).toEqual([publicKey])
  expect(Date.parse(body.expires_at) - Date.now()).toBeLessThanOrEqual(8 * 3600 * 1000)
  expect(body.reason).toBe('Pilot acceptance')
})

it('requires reason for revoke/reset and reports server conflicts without claiming success', async () => {
  vi.mocked(request).mockImplementation((_, init) => init?.method === 'POST' ? Promise.reject(new ApiError(409, 'conflict')) : Promise.resolve(status()))
  render(<SupportAccess deviceId="one" canWrite />)
  await screen.findByText('Установлен · 1.0.0')
  expect((screen.getByRole('button', { name: 'Сбросить регистрацию ключей' }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.change(screen.getByLabelText('Причина изменения доступа'), { target: { value: 'Replace lost keys' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сбросить регистрацию ключей' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('конфликт'))
  expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/support-access/devices/one/reset-registration', expect.objectContaining({ body: JSON.stringify({ reason: 'Replace lost keys' }) }))
})
