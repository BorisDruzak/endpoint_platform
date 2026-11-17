import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { SupportAccess } from './SupportAccess'
import { request, ApiError } from './api'
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }))
afterEach(() => { cleanup(); vi.resetAllMocks() })
const key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB'
const status = () => ({
  policy: { platform: 'linux_amd64', device_id: 'linux', enabled: false, expires_at: null, operator_public_keys: [],
    linux_admin_username: null, linux_admin_uid: null, gateway_host: 'endpoint.sosnadmin.local', gateway_port: 2222, remote_port: 32001 },
  configured_policy: { enabled: true, expires_at: '2030-01-01T00:00:00Z', operator_public_keys: [key], linux_admin_username: 'root', linux_admin_uid: 0 },
  installed: true, component_version: '1.0.0', reported_at: new Date().toISOString(), tunnel_connected: true,
  host_public_key: key, access_verified_at: null, reset_registration_allowed: false,
})
function respond() {
  vi.mocked(request).mockImplementation(path => Promise.resolve(path.endsWith('/platform')
    ? { device_id: 'linux', platform: 'linux_amd64' } : status()))
}
it('uses verified Linux platform and retains root UID zero from stored intent without enabling it', async () => {
  respond()
  render(<SupportAccess deviceId="linux" canWrite />)
  const account = await screen.findByLabelText('Существующий администратор Linux')
  expect((account as HTMLInputElement).value).toBe('root')
  expect((screen.getByLabelText('UID администратора Linux') as HTMLInputElement).value).toBe('0')
  expect(screen.getByText(/Сохранённая настройка: включена/)).toBeTruthy()
  expect(screen.getByText('Выключена')).toBeTruthy()
  expect(screen.queryByText(/ДОМЕН/)).toBeNull()
  expect(screen.getByText('Оператор не подтвердил SSH-доступ')).toBeTruthy()
  expect(vi.mocked(request).mock.calls.every(([, init]) => !init)).toBe(true)
  fireEvent.change(screen.getByLabelText('Причина изменения доступа'), { target: { value: 'Explicit Linux access' } })
  fireEvent.click(screen.getByRole('button', { name: 'Включить доступ' }))
  await waitFor(() => expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
  const [path, init] = vi.mocked(request).mock.calls.find(([, init]) => init?.method === 'PUT')!
  const body = JSON.parse(String(init?.body))
  expect(path).toBe('/api/admin/support-access/linux/devices/linux/policy')
  expect(body).toMatchObject({ platform: 'linux_amd64', linux_admin_username: 'root', linux_admin_uid: 0, operator_public_keys: [key] })
  expect(body).not.toHaveProperty('windows_admin_username')
})
it.each(['', '-1', '1.5', '1e3', '2147483648'])('rejects non-strict UID %s', async uid => {
  respond(); render(<SupportAccess deviceId="linux" canWrite />)
  fireEvent.change(await screen.findByLabelText('UID администратора Linux'), { target: { value: uid } })
  fireEvent.change(screen.getByLabelText('Причина изменения доступа'), { target: { value: 'Validate exact identity' } })
  fireEvent.click(screen.getByRole('button', { name: 'Включить доступ' }))
  expect(await screen.findByRole('alert')).toBeTruthy()
  expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method)).toBe(false)
})
it.each([null, 'darwin', 'windows'])('blocks unknown or unverified platform %s', async platform => {
  vi.mocked(request).mockResolvedValue({ device_id: 'linux', platform })
  render(<SupportAccess deviceId="linux" canWrite />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('Платформа'))
  expect(screen.queryByRole('button', { name: 'Включить доступ' })).toBeNull()
  expect(vi.mocked(request).mock.calls).toHaveLength(1)
})
it('never falls back to Windows after Linux status denial', async () => {
  vi.mocked(request).mockImplementation(path => path.endsWith('/platform')
    ? Promise.resolve({ device_id: 'linux', platform: 'linux_amd64' }) : Promise.reject(new ApiError(403, 'Denied')))
  render(<SupportAccess deviceId="linux" canWrite />)
  await screen.findByRole('alert')
  expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([
    '/api/admin/support-access/devices/linux/platform', '/api/admin/support-access/linux/devices/linux'])
})
it('refuses an unknown platform in a status response after positive Windows discovery', async () => {
  vi.mocked(request).mockImplementation(path => Promise.resolve(path.endsWith('/platform')
    ? { device_id: 'linux', platform: 'windows_amd64' } : { ...status(), policy: { ...status().policy, platform: 'darwin' } }))
  render(<SupportAccess deviceId="linux" canWrite />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('Платформа ответа'))
  expect(screen.queryByRole('button', { name: 'Включить доступ' })).toBeNull()
})
it('clears Linux fields immediately when switching to an unknown device', async () => {
  respond(); const { rerender } = render(<SupportAccess deviceId="linux" canWrite />)
  await screen.findByLabelText('UID администратора Linux')
  vi.mocked(request).mockResolvedValue({ device_id: 'other', platform: null })
  rerender(<SupportAccess deviceId="other" canWrite />)
  expect(screen.queryByLabelText('UID администратора Linux')).toBeNull()
  await screen.findByRole('alert')
})

it('disables masked effective policy without erasing stored administrator and approved keys', async () => {
  respond(); render(<SupportAccess deviceId="linux" canWrite />)
  await screen.findByLabelText('UID администратора Linux')
  fireEvent.change(screen.getByLabelText('Причина изменения доступа'), { target: { value: 'Disable retained intent' } })
  fireEvent.click(screen.getByRole('button', { name: 'Выключить доступ' }))
  await waitFor(() => expect(vi.mocked(request).mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true))
  const [, init] = vi.mocked(request).mock.calls.find(([, init]) => init?.method === 'PUT')!
  expect(JSON.parse(String(init?.body))).toMatchObject({ enabled: false, expires_at: null,
    linux_admin_username: 'root', linux_admin_uid: 0, operator_public_keys: [key] })
})

it('records only explicit operator attestation on the Linux endpoint', async () => {
  vi.mocked(request).mockImplementation(path => Promise.resolve(path.endsWith('/platform') ? { device_id: 'linux', platform: 'linux_amd64' } : {
    ...status(), policy: { ...status().policy, enabled: true, expires_at: '2030-01-01T00:00:00Z' },
  }))
  render(<SupportAccess deviceId="linux" canWrite />)
  await screen.findByLabelText('UID администратора Linux')
  fireEvent.change(screen.getByLabelText('Причина изменения доступа'), { target: { value: 'Verified actual administrator command' } })
  fireEvent.click(screen.getByRole('button', { name: 'Подтвердить выполненную SSH-команду' }))
  expect(await screen.findByRole('status')).toHaveProperty('textContent', expect.stringContaining('Console не выполнял SSH-команду'))
  expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/support-access/linux/devices/linux/verify-access', expect.objectContaining({ method: 'POST' }))
})
