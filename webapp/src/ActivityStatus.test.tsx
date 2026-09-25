import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { DeviceActivityStatus } from './ActivityStatus'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('labels offline activity as a last observation rather than a live state', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ data: {
    collected_at: '2026-09-25T11:00:00Z', last_observed_at: '2026-09-25T11:00:00Z',
    online: false, fresh: false,
    sections: { user_login: 'operator', session_state: 'ACTIVE', idle_seconds: 12,
      foreground: null, browser: null },
  } }) })))
  render(<DeviceActivityStatus deviceId="device-1" />)
  expect(await screen.findByText('Устройство не в сети. Показано последнее наблюдение.')).toBeTruthy()
  expect(screen.getByText('Последнее состояние')).toBeTruthy()
  expect(screen.getByText('Активен')).toBeTruthy()
  expect(screen.queryByText('Состояние')).toBeNull()
})

it('shows an empty state when no activity has been observed', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ data: null }) })))
  render(<DeviceActivityStatus deviceId="device-1" />)
  expect(await screen.findByText('Данные об активности ещё не получены.')).toBeTruthy()
})
