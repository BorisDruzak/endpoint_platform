import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { WorktimeLoginMethods } from './WorktimeLoginMethods'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('offers Helpdesk with the fixed local handoff and keeps explicit AD recovery', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ helpdesk_login_enabled: true }) })))
  render(<WorktimeLoginMethods adHref="/auth/employee/login?worktime=1" allowHelpdesk />)
  expect((await screen.findByRole('link', { name: 'Войти через Helpdesk' })).getAttribute('href')).toBe('/auth/worktime/helpdesk/login')
  expect(screen.getByRole('link', { name: 'Войти через AD' }).getAttribute('href')).toBe('/auth/employee/login?worktime=1')
})

it('keeps companion and DLP login AD-only without querying Helpdesk', () => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch)
  render(<WorktimeLoginMethods adHref="/auth/employee/login" allowHelpdesk={false} />)
  expect(screen.queryByRole('link', { name: 'Войти через Helpdesk' })).toBeNull()
  expect(fetch).not.toHaveBeenCalled()
})

it('keeps AD recovery when the handoff option is disabled or unavailable', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false })))
  render(<WorktimeLoginMethods adHref="/auth/employee/login?worktime=1" allowHelpdesk />)
  expect(screen.getByRole('link', { name: 'Войти через AD' })).toBeTruthy()
  expect(screen.queryByRole('link', { name: 'Войти через Helpdesk' })).toBeNull()
})
