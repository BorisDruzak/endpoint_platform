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
  expect(screen.getByRole('option', { name: '3.2.158 · EndpointAgentSetup-3.2.158-r3-x64.exe' })).toBeTruthy()
  expect(screen.getByRole('option', { name: '3.2.158 · EndpointAgentSetup-3.2.158-r2-x64.exe' })).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Полный Setup'), { target: { value: 'release' } })
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
