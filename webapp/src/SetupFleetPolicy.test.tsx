import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { SetupFleetPolicy } from './SetupFleetPolicy'
import { request, ApiError } from './api'
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }))
afterEach(() => { cleanup(); vi.clearAllMocks() })
const releases = [{ id: 'release', version: '3.2.158', artifact_name: 'Setup158-r3.exe' }]
const devices = [{ id: 'one', display_name: 'Windows one' }, { id: 'two', display_name: 'Windows two' }]
const policy = { revision: 4, enabled: false, release_id: 'release', scope: 'all_active', device_ids: [], max_parallel: 1, reason: 'Canary passed', safe_code: null }
function fixtures(qualified = true) {
  vi.mocked(request).mockImplementation(async (path, options) => {
    if (path.endsWith('/preview')) return { read_only: true, counts: { eligible: 1, already_current: 1 }, active_chains: 0, available_slots: 1, evaluated_count: 2, truncated: false, data: [] }
    if (options?.method === 'PUT') return { data: { ...policy, ...JSON.parse(String(options.body)), revision: 5 } }
    return { data: policy, qualifications: { release: qualified ? [{ source_foundation: '3.2.156', expires_at: '2026-12-01' }] : [] }, active_chains: 0, decisions: [] }
  })
}
it('previews without saving, then enables exact release with expected revision and bounded parallelism', async () => {
  fixtures(); render(<SetupFleetPolicy canWrite releases={releases} devices={devices} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр охвата' }))
  expect(await screen.findByText(/Готовы: 1/)).toBeTruthy()
  expect(vi.mocked(request).mock.calls.some(([, o]) => o?.method === 'PUT')).toBe(false)
  fireEvent.click(screen.getByLabelText('Включить автоматическое обновление'))
  fireEvent.change(screen.getByLabelText('Одновременных цепочек'), { target: { value: '2' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить политику' }))
  await waitFor(() => expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/setup-updates/fleet', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ expected_revision: 4, enabled: true, release_id: 'release', scope: 'all_active', device_ids: [], max_parallel: 2, reason: 'Canary passed' }) })))
})
it('sends explicitly selected wave and keeps it through preview', async () => {
  fixtures(); render(<SetupFleetPolicy canWrite releases={releases} devices={devices} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  fireEvent.change(screen.getByLabelText('Охват обновления'), { target: { value: 'selected' } })
  fireEvent.click(screen.getByLabelText('Windows two'))
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр охвата' }))
  await waitFor(() => expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/setup-updates/fleet/preview', expect.objectContaining({ body: JSON.stringify({ release_id: 'release', scope: 'selected', device_ids: ['two'], max_parallel: 1 }), method: 'POST' })))
})
it('keeps unqualified fleet disabled and does not offer mutation to read-only users', async () => {
  fixtures(false); const { unmount } = render(<SetupFleetPolicy canWrite releases={releases} devices={devices} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  expect((screen.getByLabelText('Включить автоматическое обновление') as HTMLInputElement).disabled).toBe(true)
  expect(screen.getByText(/Нет действующей квалификации/)).toBeTruthy()
  unmount(); render(<SetupFleetPolicy canWrite={false} releases={releases} devices={devices} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  expect(screen.queryByRole('button', { name: 'Сохранить политику' })).toBeNull()
})
it('retains draft and explains optimistic conflict instead of claiming a save', async () => {
  fixtures(); const implementation = vi.mocked(request).getMockImplementation()!
  vi.mocked(request).mockImplementation((path, options) => options?.method === 'PUT' ? Promise.reject(new ApiError(409, 'conflict')) : implementation(path, options))
  render(<SetupFleetPolicy canWrite releases={releases} devices={devices} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  fireEvent.change(screen.getByLabelText('Причина политики'), { target: { value: 'Keep my draft' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить политику' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('другим администратором'))
  expect((screen.getByLabelText('Причина политики') as HTMLInputElement).value).toBe('Keep my draft')
})
it('reloads current server revision when discarding a conflicting draft', async () => {
  fixtures(); const implementation = vi.mocked(request).getMockImplementation()!
  let conflict = false
  vi.mocked(request).mockImplementation((path, options) => {
    if (options?.method === 'PUT') { conflict = true; return Promise.reject(new ApiError(409, 'conflict')) }
    if (conflict) return Promise.resolve({ data: { ...policy, revision: 5, reason: 'Other administrator choice' }, qualifications: { release: [] }, active_chains: 0, decisions: [] })
    return implementation(path, options)
  })
  render(<SetupFleetPolicy canWrite releases={releases} devices={devices} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  fireEvent.change(screen.getByLabelText('Причина политики'), { target: { value: 'My stale draft' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить политику' }))
  await screen.findByRole('alert')
  fireEvent.click(screen.getByRole('button', { name: 'Сбросить изменения' }))
  await waitFor(() => expect((screen.getByLabelText('Причина политики') as HTMLInputElement).value).toBe('Other administrator choice'))
  expect(screen.getByText(/Версия политики: 5/)).toBeTruthy()
})

it('clears the previous coverage preview when the draft target changes', async () => {
  fixtures()
  render(<SetupFleetPolicy canWrite releases={[...releases, { id: 'next', version: '3.2.165', artifact_name: 'Setup165.exe' }]} devices={devices} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр охвата' }))
  await screen.findByText(/Готовы: 1/)
  fireEvent.change(screen.getByLabelText('Целевой полный Setup'), { target: { value: 'next' } })
  expect(screen.queryByText(/Готовы: 1/)).toBeNull()
})

it('invalidates preview when a refreshed persisted policy changes the clean target', async () => {
  fixtures()
  const implementation = vi.mocked(request).getMockImplementation()!
  let finish: (value: unknown) => void = () => {}
  let refreshed = false
  vi.mocked(request).mockImplementation((path, options) => {
    if (path.endsWith('/preview')) return new Promise(resolve => { finish = resolve })
    if (refreshed) return Promise.resolve({ data: { ...policy, revision: 5, release_id: 'next' }, qualifications: {}, active_chains: 0, decisions: [] })
    return implementation(path, options)
  })
  const props = { canWrite: true, releases: [...releases, { id: 'next', version: '3.2.165', artifact_name: 'Setup165.exe' }], devices }
  const { rerender } = render(<SetupFleetPolicy {...props} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр охвата' }))
  refreshed = true
  rerender(<SetupFleetPolicy {...props} revision={1} />)
  await screen.findByText(/Версия политики: 5/)
  finish({ read_only: true, counts: { eligible: 99 }, active_chains: 0, available_slots: 1, evaluated_count: 99, truncated: false, data: [] })
  await waitFor(() => expect((screen.getByRole('button', { name: 'Предпросмотр охвата' }) as HTMLButtonElement).disabled).toBe(false))
  expect((screen.getByLabelText('Целевой полный Setup') as HTMLSelectElement).value).toBe('next')
  expect(screen.queryByText(/Готовы: 99/)).toBeNull()
})

it('does not submit a policy form from a read-only view', async () => {
  fixtures()
  render(<SetupFleetPolicy canWrite={false} releases={releases} devices={devices} revision={0} />)
  await screen.findByText(/Версия политики: 4/)
  fireEvent.submit(screen.getByLabelText('Охват обновления').closest('form')!)
  expect(vi.mocked(request).mock.calls.some(([, options]) => options?.method === 'PUT')).toBe(false)
})
