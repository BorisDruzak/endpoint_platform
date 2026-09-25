import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { PolicyCatalog } from './PolicyCatalog'
import { getSession } from './api'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const policy = {
  schema_version: 'endpoint_policy_v1', policy_id: 'policy-1', policy_version: 1,
  activity: { enabled: true, idle_threshold_seconds: 600, foreground_application: true, browser_context: true },
  dlp: { usb_device_events: 'audit', removable_write_events: 'disabled', print_events: 'audit',
    browser_upload_events: 'audit', browser_paste_events: 'audit' },
  browser_sensor: { required: true, deployment_mode: 'agent_managed' },
  event_retention: { security_event_days: 30 },
}

it('shows the active policy and its bounded typed sections', async () => {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    const data = path.includes('/assignments/default')
      ? { data: { policy_id: 'policy-1', policy_version_id: 'version-1', policy_version: 1,
        policy_name: 'Муниципальная', scope: 'default', device_id: null, assigned_at: '2026-09-25T12:00:00Z' } }
      : path === '/api/admin/console/policies/policy-1'
        ? { data: { id: 'policy-1', name: 'Муниципальная', created_at: '2026-09-24T12:00:00Z',
          versions_total: 1 } }
      : path.includes('/versions/version-1')
        ? { data: { version_id: 'version-1', policy_version: 1, digest: 'digest',
          created_at: '2026-09-25T12:00:00Z', policy } }
        : path.includes('/versions')
          ? { data: [{ version_id: 'version-1', policy_version: 1, digest: 'digest',
            created_at: '2026-09-25T12:00:00Z' }], total: 1, limit: 50, offset: 0 }
          : { data: [{ id: 'policy-other', name: 'Новая политика', created_at: '2026-09-25T12:00:00Z',
            versions_total: 1 }], total: 1, limit: 50, offset: 0 }
    return { ok: true, status: 200, json: async () => data }
  }))
  render(<PolicyCatalog />)
  const section = (await screen.findByRole('heading', { name: 'Активная политика' })).closest('section')!
  expect(await within(section).findByText('По умолчанию')).toBeTruthy()
  expect(within(section).getAllByText('Муниципальная')).toHaveLength(2)
  expect(within(section).getAllByText('Версия 1')).toHaveLength(2)
  expect(screen.getByRole('heading', { name: 'Активность' })).toBeTruthy()
  expect(screen.getByRole('heading', { name: 'Browser Sensor' })).toBeTruthy()
  expect(screen.getByRole('heading', { name: 'DLP' })).toBeTruthy()
  expect(screen.getByText('Хранение событий')).toBeTruthy()
})

it('creates a typed next policy version with a changed Browser Sensor owner', async () => {
  let created: Record<string, unknown> | null = null
  let latest = 1
  vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
    if (path === '/api/admin/console/session') return { ok: true, status: 200,
      json: async () => ({ username: 'operator', scopes: [], csrf_token: 'csrf-test' }) }
    if (path.includes('/assignments/default')) return { ok: true, status: 200,
      json: async () => ({ data: { policy_id: 'policy-1', policy_version_id: 'version-1',
        policy_version: 1, policy_name: 'Муниципальная', scope: 'default',
        device_id: null, assigned_at: '2026-09-25T12:00:00Z' } }) }
    if (path.includes('/versions') && init?.method === 'POST') {
      created = JSON.parse(String(init.body)) as Record<string, unknown>
      latest = 2
      return { ok: true, status: 201, json: async () => ({ data: { policy_id: 'policy-1',
        version_id: 'version-2', policy_version: 2, digest: 'digest-2' } }) }
    }
    if (path.includes('/versions/version-2')) return { ok: true, status: 200,
      json: async () => ({ data: { version_id: 'version-2', policy_version: 2,
        digest: 'digest-2', created_at: '2026-09-25T13:00:00Z',
        policy: { ...policy, policy_version: 2, browser_sensor: { required: true, deployment_mode: 'external_managed' } } } }) }
    if (path.includes('/versions/version-1')) return { ok: true, status: 200,
      json: async () => ({ data: { version_id: 'version-1', policy_version: 1,
        digest: 'digest-1', created_at: '2026-09-25T12:00:00Z', policy } }) }
    if (path.includes('/versions')) return { ok: true, status: 200,
      json: async () => ({ data: Array.from({ length: latest }, (_, index) => ({
        version_id: `version-${latest - index}`, policy_version: latest - index,
        digest: `digest-${latest - index}`, created_at: '2026-09-25T12:00:00Z',
      })), total: latest, limit: 50, offset: 0 }) }
    return { ok: true, status: 200, json: async () => ({ data: [{ id: 'policy-1', name: 'Муниципальная',
      created_at: '2026-09-25T12:00:00Z', versions_total: latest }], total: 1, limit: 50, offset: 0 }) }
  }))
  await getSession()
  render(<PolicyCatalog />)
  expect(await screen.findByText('Хранение событий')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Создать новую версию' }))
  fireEvent.change(screen.getByLabelText('Управление Browser Sensor'), { target: { value: 'external_managed' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить версию' }))
  expect(await screen.findByText('Версия 2 создана')).toBeTruthy()
  expect((created as { policy: typeof policy } | null)?.policy.policy_version).toBe(2)
  expect((created as { policy: typeof policy } | null)?.policy.browser_sensor.deployment_mode).toBe('external_managed')
  expect((created as { policy: typeof policy } | null)?.policy.dlp.usb_device_events).toBe('audit')
  await waitFor(() => expect((screen.getByLabelText('Версия') as HTMLSelectElement).value).toBe('version-2'))
})

it('assigns the selected immutable version as default and to a device', async () => {
  const assigned: { path: string; body: string }[] = []
  const deviceId = 'a57a8091-8a96-4207-ac32-fcc013340849'
  vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
    if (path === '/api/admin/console/session') return { ok: true, status: 200,
      json: async () => ({ username: 'operator', scopes: [], csrf_token: 'csrf-test' }) }
    if (init?.method === 'PUT') {
      assigned.push({ path, body: String(init.body) })
      return { ok: true, status: 200, json: async () => ({ data: {
        scope: path.endsWith('/default') ? 'default' : 'device',
        device_id: path.endsWith('/default') ? null : deviceId,
        policy_version_id: 'version-1', assigned_at: '2026-09-25T12:00:00Z',
      } }) }
    }
    if (path.includes('/assignments/default')) return { ok: true, status: 200,
      json: async () => ({ data: null }) }
    if (path.includes('/versions/version-1')) return { ok: true, status: 200,
      json: async () => ({ data: { version_id: 'version-1', policy_version: 1,
        digest: 'digest', created_at: '2026-09-25T12:00:00Z', policy } }) }
    if (path.includes('/versions')) return { ok: true, status: 200,
      json: async () => ({ data: [{ version_id: 'version-1', policy_version: 1,
        digest: 'digest', created_at: '2026-09-25T12:00:00Z' }], total: 1, limit: 50, offset: 0 }) }
    return { ok: true, status: 200, json: async () => ({ data: [{ id: 'policy-1', name: 'Муниципальная',
      created_at: '2026-09-25T12:00:00Z', versions_total: 1 }], total: 1, limit: 50, offset: 0 }) }
  }))
  await getSession()
  render(<PolicyCatalog />)
  expect(await screen.findByText('Хранение событий')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Сделать политикой по умолчанию' }))
  expect(await screen.findByText('Политика назначена по умолчанию')).toBeTruthy()
  fireEvent.change(screen.getByLabelText('ID устройства'), { target: { value: deviceId } })
  fireEvent.click(screen.getByRole('button', { name: 'Назначить устройству' }))
  expect(await screen.findByText('Политика назначена устройству')).toBeTruthy()
  expect(assigned).toEqual([
    { path: '/api/admin/console/policies/assignments/default', body: '{"policy_version_id":"version-1"}' },
    { path: `/api/admin/console/policies/assignments/devices/${deviceId}`,
      body: '{"policy_version_id":"version-1"}' },
  ])
})

it('creates the first policy from safe typed defaults', async () => {
  let created: { name: string; policy: typeof policy } | null = null
  vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
    if (path === '/api/admin/console/session') return { ok: true, status: 200,
      json: async () => ({ username: 'operator', scopes: [], csrf_token: 'csrf-test' }) }
    if (path === '/api/admin/console/policies' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as { name: string; policy: typeof policy }
      created = body
      return { ok: true, status: 201, json: async () => ({ data: {
        policy_id: body.policy.policy_id, version_id: 'version-1', policy_version: 1, digest: 'digest',
      } }) }
    }
    if (path.includes('/assignments/default')) return { ok: true, status: 200,
      json: async () => ({ data: null }) }
    const current = created as { name: string; policy: typeof policy } | null
    if (path.includes('/versions/version-1') && current) return { ok: true, status: 200,
      json: async () => ({ data: { version_id: 'version-1', policy_version: 1,
        digest: 'digest', created_at: '2026-09-25T12:00:00Z', policy: current.policy } }) }
    if (path.includes('/versions') && current) return { ok: true, status: 200,
      json: async () => ({ data: [{ version_id: 'version-1', policy_version: 1,
        digest: 'digest', created_at: '2026-09-25T12:00:00Z' }], total: 1, limit: 50, offset: 0 }) }
    return { ok: true, status: 200, json: async () => ({
      data: current ? [{ id: current.policy.policy_id, name: current.name,
        created_at: '2026-09-25T12:00:00Z', versions_total: 1 }] : [],
      total: current ? 1 : 0, limit: 50, offset: 0,
    }) }
  }))
  await getSession()
  render(<PolicyCatalog />)
  expect(await screen.findByText('Политики ещё не созданы.')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Создать политику' }))
  fireEvent.change(screen.getByLabelText('Название новой политики'), { target: { value: 'Пилотная' } })
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить политику' }))
  expect(await screen.findByText('Политика создана')).toBeTruthy()
  const submitted = created as { name: string; policy: typeof policy } | null
  expect(submitted?.name).toBe('Пилотная')
  expect(submitted?.policy.policy_version).toBe(1)
  expect(submitted?.policy.browser_sensor.required).toBe(false)
  expect(submitted?.policy.dlp.browser_upload_events).toBe('disabled')
  expect(submitted?.policy.dlp.removable_write_events).toBe('disabled')
  const section = screen.getByRole('heading', { name: 'Активная политика' }).closest('section')!
  expect(await within(section).findAllByText('Пилотная')).toHaveLength(2)
})
