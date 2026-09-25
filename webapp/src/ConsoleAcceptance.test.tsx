import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuditPage } from './AuditPage'
import { EnrollmentPage } from './EnrollmentPage'
import { DeviceDetailPage } from './FleetPages'
import { DeviceModules, ModulesPage } from './ModulesPage'
import { UpdatesPage } from './UpdatesPage'
import { OperationsPage } from './OperationsPage'
import { getSession } from './api'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function jsonResponse(data: unknown): Response {
  return { ok: true, status: 200, json: async () => data } as Response
}

const requestRows = [
  { id: '10000000-0000-0000-0000-000000000001', status: 'waiting_approval', hostname: 'PC-01' },
  { id: '10000000-0000-0000-0000-000000000002', status: 'review_required', hostname: 'PC-02' },
  { id: '10000000-0000-0000-0000-000000000003', status: 'denied', hostname: 'PC-03' },
  { id: '10000000-0000-0000-0000-000000000004', status: 'completed', hostname: 'PC-04' },
].map(item => ({
  ...item,
  reason: null, platform: 'windows', manufacturer: 'Example', model: 'Desktop',
  serial: 'SERIAL', macs: ['00:11:22:33:44:55'], source_address: '192.0.2.10',
  installer_release_id: '3.2.63', selected_campaign_id: null, device_id: null,
  created_at: '2026-09-24T08:00:00Z', expires_at: '2026-09-25T08:00:00Z', decided_at: null,
}))

describe('Русский интерфейс Console', () => {
  it('закрепляет доступный безопасный результат операции', async () => {
    let pinned = false
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/api/admin/console/session')) return jsonResponse({ username: 'operator', scopes: [], csrf_token: 'test-csrf' })
      if (url.endsWith('/evidence/pin') && init?.method === 'POST') {
        pinned = true
        return jsonResponse({ data: {} })
      }
      if (url.includes('/api/admin/operations?')) return jsonResponse({ data: [{
        operation_id: 'operation-1', device_id: 'device-1', device_name: 'PC-01',
        capability: 'context.diagnostic.collect', status: 'succeeded', owner: 'helpdesk',
        created_at: '2026-09-24T08:00:00Z', deadline_at: '2026-09-24T09:00:00Z',
        completed_at: '2026-09-24T08:01:00Z', duration_ms: 60000,
      }], total: 1 })
      if (url.endsWith('/api/admin/operations/operation-1')) return jsonResponse({
        data: { operation_id: 'operation-1', device_id: 'device-1', device_name: 'PC-01',
          capability: 'context.diagnostic.collect', status: 'succeeded', owner: 'helpdesk',
          created_at: '2026-09-24T08:00:00Z', deadline_at: '2026-09-24T09:00:00Z',
          completed_at: '2026-09-24T08:01:00Z', duration_ms: 60000 },
        safe_result: null, module_detail: null,
        evidence: { result_available: true, result_expires_at: pinned ? null : '2026-09-25T08:01:00Z',
          result_pinned: pinned, result_scrubbed_at: null, result_digest: 'a'.repeat(64) },
      })
      throw new Error(`Unexpected route ${url}`)
    }))
    await getSession()
    render(<MemoryRouter initialEntries={['/admin/operations']}><OperationsPage /></MemoryRouter>)
    fireEvent.click(await screen.findByRole('button', { name: 'Открыть' }))
    expect(await screen.findByText(/Результат доступен до/)).toBeTruthy()
    fireEvent.change(screen.getByRole('textbox', { name: 'Причина закрепления' }), { target: { value: 'Проверка инцидента' } })
    fireEvent.click(screen.getByRole('button', { name: 'Закрепить результат' }))
    expect(await screen.findByText(/Результат закреплён/)).toBeTruthy()
  })
  it('показывает поля инвентаризации и других профилей понятными подписями', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => jsonResponse(
      url.includes('/context/history?') ? { data: [], has_more: false } : {
        device: { id: 'device-1', display_name: 'Рабочая станция', device_identifier: 'PC-01', online: true, last_seen_at: null, agent_version: '3.2.63', hostname: 'PC-01', os_name: 'Windows 11', os_version: '11', current_user: 'operator' },
        capabilities: [{ capability: 'system.resource_snapshot', display_name_ru: 'Состояние ресурсов системы', category: 'system' }],
        snapshots: [
          { id: 'inventory-1', profile: 'inventory_v1', collected_at: '2026-09-24T08:00:00Z', fresh: true, semantic_hash: null, warnings: [], sections: {
            system: { hostname: 'PC-01', platform: 'windows' },
            hardware: { bios_vendor: 'Example BIOS', baseboard_manufacturer: 'Example Board' },
            memory: { module_count: 1, modules: [{ slot: 'DIMM-1', part_number: 'RAM-8G' }] },
            storage: { physical_devices: [{ model: 'SSD', serial: 'DISK-1' }] },
            interfaces: [],
          } },
          { id: 'health-1', profile: 'health_v1', collected_at: '2026-09-24T08:00:00Z', fresh: false, semantic_hash: null, warnings: [], sections: {
            resources: { uptime_seconds: 60, free_bytes: 0 }, services: [{ name: 'Agent', status: 'active' }],
          } },
        ],
      },
    )))
    render(<MemoryRouter initialEntries={['/admin/devices/device-1']}><Routes>
      <Route path="/admin/devices/:deviceId" element={<DeviceDetailPage />} />
    </Routes></MemoryRouter>)

    await screen.findByRole('heading', { name: 'Рабочая станция' })
    expect(screen.getByText(/Пользователь: operator/)).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Поддерживаемые возможности' })).toBeTruthy()
    expect(screen.getByText('system.resource_snapshot')).toBeTruthy()
    expect(screen.getByText('Производитель BIOS')).toBeTruthy()
    expect(screen.getByText('Производитель системной платы')).toBeTruthy()
    expect(screen.getByText('Слот')).toBeTruthy()
    expect(screen.getByText('Артикул')).toBeTruthy()
    expect(screen.getByText('Серийный номер')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Контекст' }))
    expect(screen.getByText('Свежесть: Актуален')).toBeTruthy()
    expect(screen.getByText('Свежесть: Устарел')).toBeTruthy()
    expect(screen.getByText('Ресурсы')).toBeTruthy()
    expect(screen.getByText('Время работы')).toBeTruthy()
    expect(screen.getByText('Свободно')).toBeTruthy()
    expect(screen.getByText('0.0 ГБ')).toBeTruthy()
    expect(screen.getByText('Службы')).toBeTruthy()
    expect(screen.getByText('Активна')).toBeTruthy()
  })

  it('показывает текущую активность устройства из отдельной безопасной проекции', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.endsWith('/devices/device-1')) return jsonResponse({
        device: { id: 'device-1', display_name: 'Рабочая станция', device_identifier: 'PC-01',
          online: true, last_seen_at: null, agent_version: '3.2.70', hostname: 'PC-01',
          os_name: 'Windows 11', os_version: '11', current_user: 'operator' },
        snapshots: [], capabilities: [],
      })
      if (url.endsWith('/devices/device-1/activity')) return jsonResponse({ data: {
        collected_at: '2026-09-25T11:59:00Z', last_observed_at: '2026-09-25T12:00:00Z',
        fresh: true, online: true,
        sections: {
          user_login: 'operator', session_state: 'ACTIVE', idle_seconds: 23,
          foreground: { process_name: 'chrome.exe', application_category: 'browser' },
          browser: { browser_family: 'chrome', origin: 'https://example.org',
            domain: 'example.org', sensor_state: 'ACTIVE', extension_version: '0.1.0',
            last_seen_at: '2026-09-25T12:00:00Z' },
          window_title: 'MUST_NOT_LEAK',
        },
      } })
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter initialEntries={['/admin/devices/device-1']}><Routes>
      <Route path="/admin/devices/:deviceId" element={<DeviceDetailPage />} />
    </Routes></MemoryRouter>)
    await screen.findByRole('heading', { name: 'Рабочая станция' })
    fireEvent.click(screen.getByRole('button', { name: 'Активность' }))
    const activity = (await screen.findByRole('heading', { name: 'Активность' })).closest('section')!
    expect(within(activity).getByText('Активен')).toBeTruthy()
    expect(within(activity).getByText('23 с')).toBeTruthy()
    expect(within(activity).getByText('chrome.exe')).toBeTruthy()
    expect(within(activity).getByText('example.org')).toBeTruthy()
    expect(activity.textContent).not.toContain('MUST_NOT_LEAK')
  })

  it('открывает долговечные события и обновления устройства по страницам', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.endsWith('/devices/device-1')) return jsonResponse({
        device: { id: 'device-1', display_name: 'Рабочая станция', device_identifier: 'PC-01',
          online: true, last_seen_at: null, agent_version: '3.2.63', hostname: 'PC-01',
          os_name: 'Windows 11', os_version: '11', current_user: 'operator' }, snapshots: [],
      })
      if (url.includes('/events?')) {
        const older = url.includes('offset=20')
        return jsonResponse({ data: [{ event_id: older ? 'old-1' : 'new-1',
          event_kind: older ? 'RAM_CHANGED' : 'HOSTNAME_CHANGED', profile: 'inventory_v1',
          occurred_at: '2026-09-24T08:00:00Z', summary_code: older ? 'RAM_CHANGED' : 'HOSTNAME_CHANGED',
          safe_details: {} }],
          limit: 20, offset: older ? 20 : 0, has_more: !older })
      }
      if (url.includes('/updates?')) {
        const older = url.includes('offset=50')
        return jsonResponse({ data: [{ rollout_id: older ? 'older' : 'newer',
          version: older ? '3.2.61' : '3.2.63', mode: 'canary', status: 'applied',
          assigned_at: '2026-09-24T08:00:00Z', terminal_at: null, safe_reason: null }],
          total: 51, limit: 50, offset: older ? 50 : 0 })
      }
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter initialEntries={['/admin/devices/device-1']}><Routes>
      <Route path="/admin/devices/:deviceId" element={<DeviceDetailPage />} />
    </Routes></MemoryRouter>)
    await screen.findByRole('heading', { name: 'Рабочая станция' })
    fireEvent.click(screen.getByRole('button', { name: 'Изменения' }))
    const changes = screen.getByRole('heading', { name: 'Изменения' }).closest('section')!
    expect(await within(changes).findByText('Имя компьютера')).toBeTruthy()
    fireEvent.click(within(changes).getByRole('button', { name: 'Далее' }))
    expect(await within(changes).findByText('Оперативная память')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Обновления' }))
    const updates = screen.getByRole('heading', { name: 'История обновлений' }).closest('section')!
    expect(await within(updates).findByText('3.2.63')).toBeTruthy()
    fireEvent.click(within(updates).getByRole('button', { name: 'Далее' }))
    expect(await within(updates).findByText('3.2.61')).toBeTruthy()
  })

  it('показывает русские подписи фильтров и колонок аудита', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({
      data: [{
        id: '20000000-0000-0000-0000-000000000001', created_at: '2026-09-24T08:00:00Z',
        actor_kind: 'admin', actor_identifier: 'operator', action: 'endpoint.module_published',
        object_kind: 'module_version', object_identifier: '30000000-0000-0000-0000-000000000001',
        request_id: 'request-1', details: {},
      }], total: 1, limit: 50, offset: 0,
    })))
    render(<MemoryRouter><AuditPage /></MemoryRouter>)

    await screen.findByRole('heading', { name: 'События' })
    expect(screen.getByLabelText('Исполнитель')).toBeTruthy()
    expect(screen.getByLabelText('Действие')).toBeTruthy()
    expect(screen.getByLabelText('ID запроса')).toBeTruthy()
    expect(screen.getByRole('columnheader', { name: 'Исполнитель' })).toBeTruthy()
    expect(screen.getByText('Публикация модуля')).toBeTruthy()
  })

  it('называет редактор модулей по-русски', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => jsonResponse(
      url.includes('module-capabilities')
        ? { data: { items: [] } }
        : { data: [], total: 0, limit: 50, offset: 0 },
    )))
    render(<MemoryRouter><ModulesPage /></MemoryRouter>)

    await screen.findByRole('heading', { name: 'Модули' })
    expect(screen.getByText('РЕДАКТОР МОДУЛЕЙ')).toBeTruthy()
  })

  it('показывает описание возможности и правила её параметров', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => jsonResponse(
      url.includes('module-capabilities')
        ? { data: { items: [{
          capability: 'dns.resolve', display_name: 'Разрешить DNS-имя', category: 'network', category_display_name_ru: 'Сеть', policy: 'network_target_policy', platforms: ['linux_amd64'],
          minimum_agent_version: '3.2.63', risk: 'safe_read', consent_required: false,
          feature_flag: 'endpoint_network_primitives_enabled', parameters: [{
            name: 'target', value_type: 'string', required: true, allowed_sources: ['input', 'literal'],
            enum_values: null, minimum: null, maximum: null, default_literal: null, secret: false,
          }],
        }] } }
        : { data: [], total: 0, limit: 50, offset: 0 },
    )))
    render(<MemoryRouter><ModulesPage /></MemoryRouter>)

    expect(await screen.findByText('Разрешить DNS-имя')).toBeTruthy()
    const catalog = screen.getByRole('heading', { name: 'Каталог возможностей' }).closest('section')!
    expect(within(catalog).getByText('dns.resolve')).toBeTruthy()
    expect(within(catalog).getByRole('heading', { name: 'Сеть' })).toBeTruthy()
    expect(within(catalog).getByText(/Policy:/)).toBeTruthy()
    expect(within(catalog).getByText(/Безопасное чтение/)).toBeTruthy()
    expect(within(catalog).getByText(/Согласие: не требуется/)).toBeTruthy()
    expect(within(catalog).getByText((_, element) => element?.tagName === 'LI' && /target.*строка.*обязательный/.test(element.textContent ?? ''))).toBeTruthy()
  })

  it('разделяет заявки по очередям и показывает этапы выбранной регистрации', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/console/campaigns?')) return jsonResponse({ data: [], total: 0, limit: 50, offset: 0 })
      if (url.includes('/api/admin/console/enrollment/requests?')) {
        const queue = new URL(url, 'https://example.test').searchParams.get('queue')
        const statusByQueue: Record<string, string> = { pending: 'waiting_approval', review: 'review_required', denied: 'denied', completed: 'completed' }
        const rows = requestRows.filter(item => statusByQueue[queue ?? ''] === item.status)
        return jsonResponse({ data: rows, total: rows.length, limit: 50, offset: 0 })
      }
      if (url.includes('/enrollment/requests?')) return jsonResponse({ requests: requestRows })
      if (url.includes('/enrollment/requests/')) return jsonResponse({ data: requestRows[0] })
      if (url.includes('/enrollment/windows-summary')) return jsonResponse({ status: 'none', enrollment_mode: null, label: null })
      if (url.includes('/installer/releases')) return jsonResponse({ data: [] })
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter><EnrollmentPage /></MemoryRouter>)

    fireEvent.click(screen.getByRole('button', { name: 'Запросы регистрации' }))
    await screen.findByText('PC-01')
    expect(screen.getByRole('heading', { name: 'Ожидают подтверждения' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Требуют проверки' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Отклонены' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Завершены' })).toBeTruthy()

    fireEvent.click(screen.getAllByRole('button', { name: 'Подробнее' })[0])
    expect(await screen.findByRole('heading', { name: 'Этапы регистрации' })).toBeTruthy()
    expect(screen.getByText('Решение оператора')).toBeTruthy()
  })

  it('загружает следующую страницу внутри очереди регистрации', async () => {
    const firstPage = Array.from({ length: 50 }, (_, index) => ({
      ...requestRows[0],
      id: `40000000-0000-0000-0000-${String(index).padStart(12, '0')}`,
      hostname: `PC-${String(index).padStart(2, '0')}`,
    }))
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/console/campaigns?')) return jsonResponse({ data: [], total: 0, limit: 50, offset: 0 })
      if (url.includes('/enrollment/windows-summary')) return jsonResponse({ status: 'none', enrollment_mode: null, label: null })
      if (url.includes('/installer/releases')) return jsonResponse({ data: [] })
      if (url.includes('/api/admin/console/enrollment/requests?')) {
        const query = new URL(url, 'https://example.test').searchParams
        if (query.get('queue') === 'pending') return jsonResponse({
          data: query.get('offset') === '50' ? [{ ...requestRows[0], hostname: 'PC-51' }] : firstPage,
          total: 51, limit: 50, offset: Number(query.get('offset') ?? 0),
        })
        return jsonResponse({ data: [], total: 0, limit: 50, offset: 0 })
      }
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter><EnrollmentPage /></MemoryRouter>)

    fireEvent.click(screen.getByRole('button', { name: 'Запросы регистрации' }))
    const pending = (await screen.findByRole('heading', { name: 'Ожидают подтверждения' })).closest('section')!
    expect(within(pending).getByText('PC-00')).toBeTruthy()
    fireEvent.click(within(pending).getByRole('button', { name: 'Далее' }))
    expect(await screen.findByText('PC-51')).toBeTruthy()
  })

  it('показывает русские подписи установщика и политики кампании', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/console/campaigns?')) return jsonResponse({ data: [], total: 0, limit: 50, offset: 0 })
      if (url.includes('/enrollment/windows-summary')) return jsonResponse({ status: 'none', enrollment_mode: null, label: null })
      if (url.includes('/installer/releases')) return jsonResponse({ data: [{
        id: '50000000-0000-0000-0000-000000000001', version: '3.2.63', agent_version: '3.2.63',
        filename: 'EndpointAgentSetup-3.2.63-x64.exe', setup_sha256: 'a'.repeat(64), msi_sha256: 'b'.repeat(64),
        source_commit: 'abc123', msi_source_commit: 'def456', authenticode_status: 'valid',
        msi_authenticode_status: 'valid', authenticode_publisher: 'Example', msi_authenticode_publisher: 'Example',
        download_url: '/api/admin/console/installer/releases/50000000-0000-0000-0000-000000000001/download',
        created_at: '2026-09-24T08:00:00Z', retired_at: null,
      }] })
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter><EnrollmentPage /></MemoryRouter>)

    await screen.findByRole('link', { name: 'Скачать установщик' })
    expect(screen.getByText('Ревизия исходного кода')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Кампании' }))
    fireEvent.click(screen.getByRole('button', { name: 'Создать кампанию' }))
    expect(screen.getByLabelText('ID политики')).toBeTruthy()
  })

  it('называет канареечное обновление и список устройств по-русски', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/updates/builds')) return jsonResponse({ data: [{
        id: '60000000-0000-0000-0000-000000000001', build_identifier: 'build-1',
        version: '3.2.63', platform: 'windows_amd64', channel: 'stable', sha256: 'a'.repeat(64),
        size: 1000, artifact_name: 'agent.msi', release_notes: null, created_at: '2026-09-24T08:00:00Z',
      }], total: 1 })
      if (url.includes('/updates/rollouts')) return jsonResponse({ data: [], total: 0 })
      if (url.includes('/console/devices')) return jsonResponse({ data: [], total: 0 })
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter><UpdatesPage canWrite /></MemoryRouter>)

    await screen.findByRole('heading', { name: 'Релизы агента' })
    fireEvent.click(screen.getByRole('button', { name: 'Развёртывания' }))
    fireEvent.click(screen.getByRole('button', { name: 'Создать канареечное обновление' }))
    expect(screen.getByRole('heading', { name: 'Канареечное обновление' })).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Релиз'), { target: { value: '60000000-0000-0000-0000-000000000001' } })
    expect(await screen.findByRole('heading', { name: 'Точный список устройств (0)' })).toBeTruthy()
  })

  it('показывает завершённые развёртывания за пределами текущей страницы', async () => {
    const history = Array.from({ length: 50 }, (_, index) => ({
      id: `70000000-0000-0000-0000-${String(index).padStart(12, '0')}`,
      version: index === 0 ? '3.2.63' : '3.2.62', mode: 'canary', status: 'completed',
      completed_at: '2026-09-24T08:00:00Z', cancelled_at: null,
    }))
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/updates/builds')) return jsonResponse({ data: [], total: 0 })
      if (url.includes('/updates/rollouts?') && url.includes('terminal=true')) {
        return jsonResponse({
          data: url.includes('offset=50') ? [{ ...history[0], id: 'history-old', version: '3.2.61' }] : history,
          total: 51, limit: 50, offset: url.includes('offset=50') ? 50 : 0,
        })
      }
      if (url.includes('/updates/rollouts?')) return jsonResponse({ data: [], total: 0 })
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter><UpdatesPage canWrite={false} /></MemoryRouter>)

    fireEvent.click(screen.getByRole('button', { name: 'История' }))
    expect(await screen.findByText('3.2.63 · Канареечное')).toBeTruthy()
    const section = screen.getByRole('heading', { name: 'История развёртываний' }).closest('section')!
    fireEvent.click(within(section).getByRole('button', { name: 'Далее' }))
    expect(await screen.findByText('3.2.61 · Канареечное')).toBeTruthy()
  })

  it('показывает следующую страницу опубликованных модулей устройства', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => jsonResponse({
      data: [{ module_key: 'network.check', display_name: url.includes('offset=50') ? 'Поздний модуль' : 'Первый модуль',
        version: '1.0.0', compatible: false, reason: 'Устройство не в сети', inputs: [] }],
      total: 51, limit: 50, offset: url.includes('offset=50') ? 50 : 0,
    })))
    render(<MemoryRouter><DeviceModules deviceId="device-1" /></MemoryRouter>)

    expect(await screen.findByText(/Первый модуль/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Далее' }))
    expect(await screen.findByText(/Поздний модуль/)).toBeTruthy()
  })

  it('показывает следующую страницу истории версий модуля', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('module-capabilities')) return jsonResponse({ data: { items: [] } })
      if (url.includes('/modules?')) return jsonResponse({
        data: [{ module_key: 'network.check', display_name: 'Проверка сети',
          versions: [{ version: url.includes('offset=50') ? '1.0.0' : '1.1.0',
            state: 'published', created_at: '2026-09-24T08:00:00Z' }] }],
        total: 51, limit: 50, offset: url.includes('offset=50') ? 50 : 0,
      })
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter><ModulesPage /></MemoryRouter>)

    const history = (await screen.findByRole('heading', { name: 'Модули и версии' })).closest('section')!
    expect(within(history).getByText('1.1.0')).toBeTruthy()
    fireEvent.click(within(history).getByRole('button', { name: 'Далее' }))
    expect(await within(history).findByText('1.0.0')).toBeTruthy()
  })

  it('показывает следующую страницу совместимых устройств лаборатории', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('module-capabilities')) return jsonResponse({ data: { items: [] } })
      if (url.includes('/modules?')) return jsonResponse({ data: [], total: 0 })
      if (url.includes('/lab-devices')) return jsonResponse({
        data: [{ id: url.includes('offset=50') ? 'device-51' : 'device-1',
          display_name: url.includes('offset=50') ? 'Лаборатория 51' : 'Лаборатория 1' }],
        total: 51, limit: 50, offset: url.includes('offset=50') ? 50 : 0,
      })
      return jsonResponse({ data: {
        id: 'version-1', module_key: 'network.check', display_name: 'Проверка сети',
        version: '1.0.0', state: 'validated',
        recipe: { schema_version: 'endpoint_recipe_module_v1', module_key: 'network.check',
          supported_platforms: ['linux_amd64'], inputs: [], steps: [] },
        validations: [], validations_total: 0, labs: [], labs_total: 0,
        passed_lab_platforms: [],
      } })
    }))
    render(<MemoryRouter initialEntries={['/admin/modules?module_key=network.check&version=1.0.0']}><ModulesPage /></MemoryRouter>)

    const form = (await screen.findByRole('heading', { name: 'Запустить испытание' })).closest('form')!
    expect(await within(form).findByRole('option', { name: 'Лаборатория 1' })).toBeTruthy()
    fireEvent.click(within(form).getByRole('button', { name: 'Далее' }))
    expect(await within(form).findByRole('option', { name: 'Лаборатория 51' })).toBeTruthy()
  })

  it('учитывает старое успешное испытание и листает историю модуля', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('module-capabilities')) return jsonResponse({ data: { items: [] } })
      if (url.includes('/modules?')) return jsonResponse({ data: [], total: 0 })
      if (url.includes('/lab-devices')) return jsonResponse({ data: [], total: 0 })
      const olderLab = url.includes('lab_offset=20')
      const olderValidation = url.includes('validation_offset=20')
      return jsonResponse({ data: {
        id: 'version-1', module_key: 'network.check', display_name: 'Проверка сети',
        version: '1.0.0', state: 'validated',
        recipe: { schema_version: 'endpoint_recipe_module_v1', module_key: 'network.check',
          supported_platforms: ['linux_amd64'], inputs: [], steps: [] },
        validations: [{ status: olderValidation ? 'succeeded' : 'failed', error_codes: [], warning_codes: [],
          validator_version: olderValidation ? 'old-validator' : 'new-validator', completed_at: '2026-09-24T08:00:00Z' }],
        validations_total: 21, validation_limit: 20, validation_offset: olderValidation ? 20 : 0,
        labs: [{ platform: 'linux_amd64', status: olderLab ? 'passed' : 'failed',
          operation_id: olderLab ? 'old-operation' : 'new-operation', device_id: 'device-1',
          tested_at: '2026-09-24T08:00:00Z' }],
        labs_total: 21, lab_limit: 20, lab_offset: olderLab ? 20 : 0,
        passed_lab_platforms: ['linux_amd64'],
      } })
    }))
    render(<MemoryRouter initialEntries={['/admin/modules?module_key=network.check&version=1.0.0']}><ModulesPage /></MemoryRouter>)

    const accept = await screen.findByRole('button', { name: 'Принять испытания' })
    expect((accept as HTMLButtonElement).disabled).toBe(false)
    expect(screen.getByText('Подтверждённые платформы: Linux x64')).toBeTruthy()
    const checks = screen.getByRole('heading', { name: 'Проверки' }).closest('section')!
    fireEvent.click(within(checks).getByRole('button', { name: 'Далее' }))
    expect(await screen.findByText(/old-validator/)).toBeTruthy()
    const labs = screen.getByRole('heading', { name: 'Лабораторные испытания' }).closest('section')!
    fireEvent.click(within(labs).getByRole('button', { name: 'Далее' }))
    expect(await screen.findByText(/Пройдено/)).toBeTruthy()
  })

  it('показывает кампании Windows на следующей странице', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/console/campaigns?')) return jsonResponse({
        data: [{ id: url.includes('offset=50') ? 'older' : 'newer',
          label: url.includes('offset=50') ? 'Старая кампания' : 'Новая кампания',
          site: null, target_platform: 'windows', expires_at: '2026-12-01T00:00:00Z',
          max_uses: 10, use_count: 0, allowed_cidrs: ['192.0.2.0/24'],
          policy: { enrollment_mode: 'manual', allowed_installer_releases: ['3.2.63'] },
          revoked_at: null, disabled_at: null }],
        total: 51, limit: 50, offset: url.includes('offset=50') ? 50 : 0,
      })
      if (url.includes('/enrollment/windows-summary')) return jsonResponse({ status: 'none', enrollment_mode: null, label: null })
      if (url.includes('/installer/releases')) return jsonResponse({ data: [], total: 0, limit: 50, offset: 0 })
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter><EnrollmentPage /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: 'Кампании' }))
    expect(await screen.findByRole('heading', { name: 'Новая кампания' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Далее' }))
    expect(await screen.findByRole('heading', { name: 'Старая кампания' })).toBeTruthy()
  })

  it('позволяет выбрать старый известный Setup release на следующей странице', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/console/campaigns?')) return jsonResponse({ data: [], total: 0, limit: 50, offset: 0 })
      if (url.includes('/enrollment/windows-summary')) return jsonResponse({ status: 'none', enrollment_mode: null, label: null })
      if (url.includes('/installer/releases')) {
        const older = url.includes('offset=50')
        return jsonResponse({ data: [{ id: older ? 'older' : 'newer',
          version: older ? '3.2.62' : '3.2.63', agent_version: older ? '3.2.62' : '3.2.63',
          filename: older ? 'EndpointAgentSetup-3.2.62-x64.exe' : 'EndpointAgentSetup-3.2.63-x64.exe',
          setup_sha256: 'a'.repeat(64), msi_sha256: 'b'.repeat(64),
          source_commit: 'abc123', msi_source_commit: 'abc123', authenticode_status: 'valid',
          msi_authenticode_status: 'valid', authenticode_publisher: 'Example', msi_authenticode_publisher: 'Example',
          download_url: '/api/admin/console/installer/releases/newer/download',
          created_at: '2026-09-24T08:00:00Z', retired_at: null,
        }], total: 51, limit: 50, offset: older ? 50 : 0 })
      }
      throw new Error(`Unexpected route ${url}`)
    }))
    render(<MemoryRouter><EnrollmentPage /></MemoryRouter>)
    await screen.findByRole('link', { name: 'Скачать установщик' })
    fireEvent.click(screen.getByRole('button', { name: 'Кампании' }))
    fireEvent.click(screen.getByRole('button', { name: 'Создать кампанию' }))
    const releases = screen.getByRole('group', { name: 'Допустимые установщики' })
    fireEvent.click(within(releases).getByRole('button', { name: 'Далее' }))
    expect(await screen.findByRole('checkbox', { name: '3.2.62' })).toBeTruthy()
    fireEvent.click(screen.getByRole('checkbox', { name: '3.2.62' }))
    expect(screen.getByText(/Выбрано: 3.2.62/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Установщик' }))
    expect(screen.getByText('EndpointAgentSetup-3.2.63-x64.exe')).toBeTruthy()
  })
})
