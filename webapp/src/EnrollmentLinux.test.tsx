import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, expect, it, vi } from 'vitest'
import { EnrollmentPage } from './EnrollmentPage'
import { request } from './api'
vi.mock('./api', () => ({ request: vi.fn() }))
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.resetAllMocks() })
it('labels Linux native enrollment and refuses approval without frozen campaign authority', async () => {
  vi.mocked(request).mockImplementation(path => Promise.resolve(path.endsWith('/requests/linux-request') ? { data: {
    id: 'linux-request', platform: 'linux', hostname: 'ALT canary', status: 'review_required', reason: 'NO_MATCHING_CAMPAIGN',
    macs: [], installer_release_id: 'native-source-id', selected_campaign_id: null, created_at: '2026-11-07T00:00:00Z', expires_at: '2026-11-08T00:00:00Z',
  } } : { data: [], total: 0, limit: 50, offset: 0 }))
  render(<MemoryRouter initialEntries={['/admin/enrollment?open=linux-request']}><EnrollmentPage /></MemoryRouter>)
  expect(await screen.findByText('Linux · проверенный источник RPM')).toBeTruthy()
  expect(screen.getByText(/Сначала требуется проверка кампании Linux/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Одобрить регистрацию' })).toBeNull()
  expect(screen.getByText(/не подтверждает завершение native/)).toBeTruthy()
})

it('approves a pending Ubuntu DEB on its observed address without requiring a prior campaign', async () => {
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  vi.mocked(request).mockImplementation(path => Promise.resolve(path.endsWith('/requests/ubuntu-request') ? { data: {
    id: 'ubuntu-request', platform: 'linux', hostname: 'openvpn', status: 'waiting_approval',
    installer_kind: 'deb', source_address: '192.168.100.30', installer_release_id: 'ubuntu-deb:3.2.192-1ubuntu1',
    selected_campaign_id: null, macs: [], created_at: '2026-11-12T00:00:00Z', expires_at: '2026-11-12T00:20:00Z',
  } } : { data: [], total: 0, limit: 50, offset: 0 }))
  render(<MemoryRouter initialEntries={['/admin/enrollment?open=ubuntu-request']}><EnrollmentPage /></MemoryRouter>)
  expect(await screen.findByText(/Ubuntu · проверенный DEB/)).toBeTruthy()
  expect(screen.queryByText(/Предыдущая карточка/)).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Одобрить регистрацию' }))
  await waitFor(() => expect(request).toHaveBeenCalledWith(
    '/api/admin/enrollment/requests/ubuntu-request/approve', { method: 'POST' },
  ))
  expect(window.confirm).toHaveBeenCalledWith('Одобрить регистрацию openvpn (192.168.100.30, Ubuntu DEB)?')
})
