import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { cleanup } from '@testing-library/react'
import { FullSetupPage } from './FullSetupPage'
import { request } from './api'
vi.mock('./api', () => ({ request: vi.fn() }))
afterEach(() => { cleanup(); vi.clearAllMocks() })
function fixtures() {
  vi.mocked(request).mockImplementation(async path => {
    if (path.endsWith('/fleet')) return { data: { revision: 0, enabled: false, release_id: null, scope: 'all_active', device_ids: [], max_parallel: 1, reason: '', safe_code: null }, qualifications: {}, active_chains: 0, decisions: [] }
    if (path.endsWith('/releases')) return { data: [
      { id: 'release', version: '3.2.158', artifact_name: 'EndpointAgentSetup-3.2.158-r3-x64.exe' },
      { id: 'older', version: '3.2.158', artifact_name: 'EndpointAgentSetup-3.2.158-r2-x64.exe' },
    ] }
    if (path.includes('/console/devices?')) return { data: [{ id: 'device', display_name: 'Test120' }] }
    if (path.endsWith('/devices/device')) return { client: null, data: [] }
    return { data: { id: 'job', status: 'preparing_client' } }
  })
}
it('assigns full Setup even when legacy client needs automatic preparation', async () => {
  fixtures(); render(<FullSetupPage canWrite initialDevice="device" revision={0} />)
  expect(await screen.findByText(/Клиент будет подготовлен автоматически/)).toBeTruthy()
  expect(screen.getByRole('option', { name: /3.2.158 · EndpointAgentSetup-3.2.158-r3-x64.exe/ })).toBeTruthy()
  expect(screen.getByRole('option', { name: /3.2.158 · EndpointAgentSetup-3.2.158-r2-x64.exe/ })).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Целевой полный Setup'), { target: { value: 'release' } })
  fireEvent.change(screen.getByLabelText('Причина'), { target: { value: 'Canary test120' } })
  fireEvent.click(screen.getByRole('button', { name: 'Обновить полным Setup' }))
  await waitFor(() => expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/setup-updates/assignments', expect.objectContaining({ method: 'POST', body: JSON.stringify({ release_id: 'release', device_id: 'device', reason: 'Canary test120' }) })))
})
it('keeps read-only role read-only', async () => {
  fixtures(); render(<FullSetupPage canWrite={false} initialDevice="device" revision={0} />)
  await screen.findByText(/Клиент будет подготовлен автоматически/)
  expect(screen.queryByRole('button', { name: 'Обновить полным Setup' })).toBeNull()
})

it('does not present sensor CPU zero as measured telemetry when no sensor was observed', async () => {
  fixtures(); const implementation = vi.mocked(request).getMockImplementation()!
  vi.mocked(request).mockImplementation(path => path.endsWith('/devices/device') ? Promise.resolve({ client: null, data: [{ id: 'job', release_id: 'release', status: 'applied', reason: 'Native accepted', updated_at: new Date().toISOString(), last_report: { proof: { soak: { sensor_count: 0, sensor_cpu_percent_max: 0, duration_seconds: 180 } } } }] }) : implementation(path))
  render(<FullSetupPage canWrite={false} initialDevice="device" revision={0} />)
  await screen.findByText('Native accepted')
  expect(screen.queryByText(/CPU датчика, максимум 0/)).toBeNull()
  expect(screen.getByText(/Датчик не наблюдался/)).toBeTruthy()
})

it('uses one exact target for canary, qualification and fleet and clears proof when target changes', async () => {
  fixtures()
  const implementation = vi.mocked(request).getMockImplementation()!
  let qualified = false
  vi.mocked(request).mockImplementation(async (path, options) => {
    if (path.endsWith('/qualifications')) { qualified = true; return { data: { evidence_assignment_id: 'accepted' } } }
    if (path.endsWith('/fleet')) return { data: { revision: 0, enabled: false, release_id: null, scope: 'all_active', device_ids: [], max_parallel: 2, reason: '', safe_code: null }, qualifications: { release: qualified ? [{ source_foundation: '3.2.158', expires_at: '2026-12-01' }] : [] }, active_chains: 0, decisions: [] }
    if (path.endsWith('/devices/device')) return { client: null, data: [
      { id: 'accepted', release_id: 'release', status: 'applied', reason: 'Actual native acceptance', updated_at: new Date().toISOString() },
      { id: 'foreign', release_id: 'older', status: 'applied', reason: 'Another artifact', updated_at: new Date().toISOString() },
      { id: 'failed', release_id: 'release', status: 'failed', reason: 'Failed native', updated_at: new Date().toISOString() },
    ] }
    return implementation(path, options)
  })
  render(<FullSetupPage canWrite initialDevice="device" revision={0} />)
  await screen.findByText('Actual native acceptance')
  expect(screen.getAllByRole('combobox').filter(e => [...(e as HTMLSelectElement).options].some(o => o.value === 'release'))).toHaveLength(1)
  fireEvent.change(screen.getByLabelText('Целевой полный Setup'), { target: { value: 'release' } })
  fireEvent.click(screen.getByRole('button', { name: 'Квалифицировать этот результат' }))
  await waitFor(() => expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/setup-updates/fleet/qualifications', expect.objectContaining({ method: 'POST', body: JSON.stringify({ release_id: 'release', evidence_assignment_id: 'accepted' }) })))
  await waitFor(() => expect((screen.getByLabelText('Включить автоматическое обновление') as HTMLInputElement).disabled).toBe(false))
  fireEvent.change(screen.getByLabelText('Целевой полный Setup'), { target: { value: 'older' } })
  expect((screen.getByLabelText('Включить автоматическое обновление') as HTMLInputElement).checked).toBe(false)
  expect((screen.getByLabelText('Включить автоматическое обновление') as HTMLInputElement).disabled).toBe(true)
  fireEvent.change(screen.getByLabelText('Причина'), { target: { value: 'Older exact canary' } })
  fireEvent.click(screen.getByRole('button', { name: 'Обновить полным Setup' }))
  await waitFor(() => expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/setup-updates/assignments', expect.objectContaining({ body: JSON.stringify({ release_id: 'older', device_id: 'device', reason: 'Older exact canary' }) })))
  expect(screen.getByRole('heading', { name: /1\. Выберите/ })).toBeTruthy()
  expect(screen.getByRole('heading', { name: /6\. Контроль/ })).toBeTruthy()
  expect(document.querySelector('form form')).toBeNull()
})

it('does not submit a retained canary draft after write permission is removed', async () => {
  fixtures()
  const { rerender } = render(<FullSetupPage canWrite initialDevice="device" revision={0} />)
  await screen.findByText(/Клиент будет подготовлен автоматически/)
  fireEvent.change(screen.getByLabelText('Целевой полный Setup'), { target: { value: 'release' } })
  fireEvent.change(screen.getByLabelText('Причина'), { target: { value: 'Retained draft' } })
  rerender(<FullSetupPage canWrite={false} initialDevice="device" revision={0} />)
  fireEvent.submit(screen.getByLabelText('Устройство').closest('form')!)
  expect(vi.mocked(request).mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
})

it('pins an edited canary to its exact EXE while another administrator changes the policy', async () => {
  fixtures()
  const implementation = vi.mocked(request).getMockImplementation()!
  let changed = false
  vi.mocked(request).mockImplementation((path, options) => path.endsWith('/fleet')
    ? Promise.resolve({ data: { revision: changed ? 2 : 1, enabled: false, release_id: changed ? 'older' : 'release', scope: 'all_active', device_ids: [], max_parallel: 1, reason: '', safe_code: null }, qualifications: {}, active_chains: 0, decisions: [] })
    : implementation(path, options))
  const { rerender } = render(<FullSetupPage canWrite initialDevice="device" revision={0} />)
  await screen.findByText(/Версия политики: 1/)
  await screen.findByText(/Клиент будет подготовлен автоматически/)
  fireEvent.change(screen.getByLabelText('Причина'), { target: { value: 'Test only A.exe' } })
  changed = true
  rerender(<FullSetupPage canWrite initialDevice="device" revision={1} />)
  await screen.findByText(/Версия политики: 2/)
  await screen.findByText(/Клиент будет подготовлен автоматически/)
  expect((screen.getByLabelText('Целевой полный Setup') as HTMLSelectElement).value).toBe('release')
  fireEvent.click(screen.getByRole('button', { name: 'Обновить полным Setup' }))
  await waitFor(() => expect(vi.mocked(request)).toHaveBeenCalledWith('/api/admin/setup-updates/assignments', expect.objectContaining({ method: 'POST', body: JSON.stringify({ release_id: 'release', device_id: 'device', reason: 'Test only A.exe' }) })))
})

it('distinguishes canary computers with the same enrollment name by hostname', async () => {
  fixtures()
  const implementation = vi.mocked(request).getMockImplementation()!
  vi.mocked(request).mockImplementation((path, options) => path.includes('/console/devices?')
    ? Promise.resolve({ data: [{ id: 'device', display_name: 'Windows AUTO', hostname: 'DESKTOP-9ST5HO2' }, { id: 'other-device', display_name: 'Windows AUTO', hostname: 'OTHER-HOST' }] })
    : implementation(path, options))
  render(<FullSetupPage canWrite revision={0} />)
  expect(await screen.findByRole('option', { name: 'DESKTOP-9ST5HO2 · Windows AUTO' })).toBeTruthy()
  expect(screen.getByRole('option', { name: 'OTHER-HOST · Windows AUTO' })).toBeTruthy()
})
