import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, expect, it, vi } from 'vitest'
import { EnrollmentPage } from './EnrollmentPage'
import { request } from './api'
vi.mock('./api', () => ({ request: vi.fn() }))
afterEach(() => { cleanup(); vi.resetAllMocks() })
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
