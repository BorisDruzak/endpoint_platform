import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { cleanup } from '@testing-library/react'
import { FullSetupPage } from './FullSetupPage'
import { request } from './api'
vi.mock('./api', () => ({ request: vi.fn() }))
afterEach(() => { cleanup(); vi.clearAllMocks() })
function fixtures() {
  vi.mocked(request).mockImplementation(async path => {
    if (path.endsWith('/releases')) return { data: [{ id: 'release', version: '3.2.158' }] }
    if (path.includes('/console/devices?')) return { data: [{ id: 'device', display_name: 'Test120' }] }
    if (path.endsWith('/devices/device')) return { client: null, data: [] }
    return { data: { id: 'job', status: 'preparing_client' } }
  })
}
it('assigns full Setup even when legacy client needs automatic preparation', async () => {
  fixtures(); render(<FullSetupPage canWrite initialDevice="device" revision={0} />)
  expect(await screen.findByText(/Клиент будет подготовлен автоматически/)).toBeTruthy()
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
