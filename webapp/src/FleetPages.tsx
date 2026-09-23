import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { request } from './api'
import { DeviceModules } from './ModulesPage'

type Device = {
  id: string; device_identifier: string; display_name: string; online: boolean
  last_seen_at: string | null; agent_version: string | null; hostname: string | null
  platform: string | null; os_name: string | null; os_version: string | null
  cpu_model: string | null; ram_bytes: number | null; current_user: string | null
  context_collected_at: string | null; context_fresh: boolean; update_status: string | null
}
type Page = { data: Device[]; total: number; limit: number; offset: number }
type DashboardData = {
  total: number; online: number; offline: number; context_stale: number
  enrollment_pending: number; updates_active: number; updates_failed: number; operations_active: number
  versions: { version: string | null; count: number }[]
  attention: { kind: string; device_id: string; label: string }[]
}
type Snapshot = { id: string; profile: string; collected_at: string; semantic_hash: string | null; warnings: string[]; sections: Record<string, unknown> }
type Detail = { device: { id: string; display_name: string; device_identifier: string; online: boolean; last_seen_at: string | null; agent_version: string | null }; snapshots: Snapshot[] }
type Change = { code: string; profile: string; collected_at: string; before_snapshot_id: string; after_snapshot_id: string; before_value: string | number | null; after_value: string | number | null }
type DeviceUpdate = { rollout_id: string; version: string; mode: string; status: string; assigned_at: string; terminal_at: string | null; safe_reason: string | null }

const dateText = (value: string | null) => value ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Нет данных'
const sizeText = (value: number | null) => value ? `${(value / 1024 ** 3).toFixed(1)} ГБ` : '—'
const valueText = (value: unknown): string => value == null || value === '' ? '—' : typeof value === 'boolean' ? (value ? 'Да' : 'Нет') : String(value)
const updateLabels: Record<string, string> = { assigned: 'Назначено', requested: 'Запрошено', scheduled: 'Запланировано', applied: 'Установлено', failed: 'Ошибка', rolled_back: 'Откат', cancelled: 'Отменено' }
const changeLabels: Record<string, string> = {
  RAM_CHANGED: 'Оперативная память', STORAGE_CHANGED: 'Накопители', HOSTNAME_CHANGED: 'Имя компьютера',
  OS_CHANGED: 'Операционная система', HARDWARE_CHANGED: 'Оборудование', NETWORK_ADAPTER_CHANGED: 'Сетевые адаптеры',
  PLATFORM_CHANGED: 'Платформа', NETWORK_CHANGED: 'Сеть', SOFTWARE_CHANGED: 'Программы', AGENT_CHANGED: 'Агент',
}
const profileLabels: Record<string, string> = {
  baseline_v1: 'Базовый профиль', health_v1: 'Состояние', network_v1: 'Сеть',
  inventory_v1: 'Инвентаризация', session_v1: 'Сеанс',
}
const fieldLabels: Record<string, string> = {
  hostname: 'Имя компьютера', platform: 'Платформа', os_name: 'ОС', os_version: 'Версия ОС',
  os_build: 'Сборка', architecture: 'Архитектура', manufacturer: 'Производитель', model: 'Модель',
  serial_number: 'Серийный номер', product_uuid: 'Product UUID', cpu_model: 'Процессор',
  total_bytes: 'Объём', module_count: 'Число модулей', modules: 'Модули памяти',
  physical_devices: 'Физические накопители', size_bytes: 'Размер', media_type: 'Тип носителя',
  bus_type: 'Шина', interfaces: 'Интерфейсы', name: 'Имя', mac: 'MAC', ipv4: 'IPv4', ipv6: 'IPv6',
  current_user_login: 'Текущий пользователь', interactive_session_present: 'Интерактивный сеанс',
  operational_state: 'Состояние', link_type: 'Тип соединения', stable_key: 'Идентификатор',
  speed_mt_s: 'Скорость MT/s', memory_type: 'Тип памяти', capacity_bytes: 'Ёмкость',
}
const collectionLabels: Record<string, string> = {
  requested: 'Запрошено', queued: 'В очереди', delivered: 'Доставлено', collecting: 'Сбор данных',
  result_received: 'Результат получен', validated: 'Проверено', completed: 'Готово', failed: 'Ошибка', expired: 'Истекло',
}

function LoadError({ message, retry }: { message: string; retry: () => void }) {
  return <section className="panel state-inline" role="alert"><p>{message}</p><button onClick={retry}>Повторить</button></section>
}

export function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    let active = true
    request<DashboardData>('/api/admin/console/dashboard').then(value => { if (active) setData(value) }).catch(reason => { if (active) setError(reason.message) })
    return () => { active = false }
  }, [revision])
  if (error) return <LoadError message={error} retry={() => { setError(''); setRevision(value => value + 1) }} />
  if (!data) return <p aria-live="polite">Загрузка сводки…</p>
  const metrics = [
    ['Всего устройств', data.total, '/admin/devices'], ['В сети', data.online, '/admin/devices?online=true'],
    ['Не в сети', data.offline, '/admin/devices?online=false'], ['Устаревший контекст', data.context_stale, '/admin/devices?context=stale'],
    ['Запросы регистрации', data.enrollment_pending, '/admin/enrollment'], ['Активные обновления', data.updates_active, '/admin/updates'],
    ['Ошибки обновлений', data.updates_failed, '/admin/devices?update=failed'], ['Активные операции', data.operations_active, '/admin/operations'],
  ] as const
  return <>
    <div className="page-heading"><div><p className="eyebrow">ОБЗОР</p><h1>Состояние парка</h1><p className="muted">Текущая сводка Endpoint Platform</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <div className="metric-grid">{metrics.map(([label, count, href]) => <Link className="metric-card" key={label} to={href}><span>{label}</span><strong>{count.toLocaleString('ru-RU')}</strong></Link>)}</div>
    <div className="dashboard-grid">
      <section className="panel"><h2>Требует внимания</h2>{data.attention.length ? <ul className="attention-list">{data.attention.map((item, index) => <li key={`${item.device_id}-${index}`}><Link to={`/admin/devices/${item.device_id}`}>{item.label}</Link><span>{item.kind === 'update_failed' ? 'Ошибка обновления' : 'Контекст устарел'}</span></li>)}</ul> : <p className="muted">Нет устройств, требующих внимания.</p>}</section>
      <section className="panel"><h2>Версии агента</h2>{data.versions.length ? <ul className="version-list">{data.versions.map(item => <li key={item.version ?? 'unknown'}><span>{item.version ?? 'Неизвестна'}</span><strong>{item.count}</strong></li>)}</ul> : <p className="muted">Пока нет зарегистрированных версий.</p>}</section>
    </div>
  </>
}

export function DevicesPage() {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  const query = params.toString()
  useEffect(() => {
    let active = true
    request<Page>(`/api/admin/console/devices?${query}`).then(value => { if (active) { setPage(value); setError('') } }).catch(reason => { if (active) setError(reason.message) })
    return () => { active = false }
  }, [query, revision])
  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    next.delete('offset')
    setParams(next)
  }
  function move(offset: number) { const next = new URLSearchParams(params); next.set('offset', String(offset)); setParams(next) }
  return <>
    <div className="page-heading"><div><p className="eyebrow">ПАРК</p><h1>Устройства</h1><p className="muted">Поиск и текущее состояние устройств</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <div className="filters panel">
      <label>Поиск<input type="search" value={params.get('search') ?? ''} onChange={event => setFilter('search', event.target.value)} placeholder="Имя или идентификатор" /></label>
      <label>Состояние<select value={params.get('online') ?? ''} onChange={event => setFilter('online', event.target.value)}><option value="">Все</option><option value="true">В сети</option><option value="false">Не в сети</option></select></label>
      <label>ОС<select value={params.get('platform') ?? ''} onChange={event => setFilter('platform', event.target.value)}><option value="">Все</option><option value="windows">Windows</option><option value="linux">ALT Linux</option></select></label>
      <label>Версия агента<input value={params.get('agent_version') ?? ''} onChange={event => setFilter('agent_version', event.target.value)} placeholder="Любая" /></label>
      <label>Контекст<select value={params.get('context') ?? ''} onChange={event => setFilter('context', event.target.value)}><option value="">Любой</option><option value="fresh">Актуален</option><option value="stale">Устарел</option></select></label>
      <label>Обновление<select value={params.get('update') ?? ''} onChange={event => setFilter('update', event.target.value)}><option value="">Любое</option><option value="none">Нет</option><option value="active">В процессе</option><option value="failed">Ошибка</option></select></label>
    </div>
    {error ? <LoadError message={error} retry={() => setRevision(value => value + 1)} /> : !page ? <p aria-live="polite">Загрузка устройств…</p> : <section className="panel table-panel"><div className="table-top"><h2>Устройства</h2><span>{page.total.toLocaleString('ru-RU')} всего</span></div>{page.data.length ? <div className="table-scroll"><table><thead><tr><th>Состояние</th><th>Устройство</th><th>Пользователь</th><th>ОС</th><th>Агент</th><th>CPU / RAM</th><th>Последняя связь</th><th>Контекст</th><th>Обновление</th><th></th></tr></thead><tbody>{page.data.map(device => <tr key={device.id}><td><span className={`status ${device.online ? 'online' : 'offline'}`}>{device.online ? 'В сети' : 'Не в сети'}</span></td><td><strong>{device.display_name}</strong><small>{device.hostname ?? device.device_identifier}</small></td><td>{device.current_user ?? '—'}</td><td>{device.os_name ?? device.platform ?? '—'}<small>{device.os_version ?? ''}</small></td><td>{device.agent_version ?? '—'}</td><td>{device.cpu_model ?? '—'}<small>{sizeText(device.ram_bytes)}</small></td><td>{dateText(device.last_seen_at)}</td><td><span className={`status ${device.context_fresh ? 'online' : 'warning'}`}>{device.context_fresh ? 'Актуален' : 'Устарел'}</span><small>{dateText(device.context_collected_at)}</small></td><td>{device.update_status ? updateLabels[device.update_status] ?? device.update_status : 'Нет'}</td><td><Link to={`/admin/devices/${device.id}`}>Открыть</Link></td></tr>)}</tbody></table></div> : <p className="empty-text">Устройства по заданным условиям не найдены.</p>}<div className="pagination"><button disabled={page.offset === 0} onClick={() => move(Math.max(0, page.offset - page.limit))}>Назад</button><span>{page.total ? `${page.offset + 1}–${Math.min(page.offset + page.limit, page.total)}` : '0'} из {page.total}</span><button disabled={page.offset + page.limit >= page.total} onClick={() => move(page.offset + page.limit)}>Далее</button></div></section>}
  </>
}

function SectionRows({ data }: { data: Record<string, unknown> }) {
  return <dl className="detail-grid">{Object.entries(data).map(([key, value]) => <div key={key}><dt>{fieldLabels[key] ?? key.replaceAll('_', ' ')}</dt><dd>{Array.isArray(value) ? value.length ? <ul>{value.map((item, index) => <li key={index}>{typeof item === 'object' && item !== null ? <SectionRows data={item as Record<string, unknown>} /> : valueText(item)}</li>)}</ul> : '—' : typeof value === 'object' && value !== null ? <SectionRows data={value as Record<string, unknown>} /> : key.endsWith('_bytes') && typeof value === 'number' ? sizeText(value) : valueText(value)}</dd></div>)}</dl>
}

export function DeviceDetailPage() {
  const { deviceId } = useParams()
  const [detail, setDetail] = useState<Detail | null>(null)
  const [changes, setChanges] = useState<Change[]>([])
  const [tab, setTab] = useState('overview')
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  const [refreshProfile, setRefreshProfile] = useState('inventory_v1')
  const [collection, setCollection] = useState<{ id: string; status: string } | null>(null)
  const [refreshError, setRefreshError] = useState('')
  const [updates, setUpdates] = useState<DeviceUpdate[] | null>(null)
  useEffect(() => {
    let active = true
    Promise.all([
      request<Detail>(`/api/admin/console/devices/${deviceId}`),
      request<{ data: Change[] }>(`/api/admin/console/devices/${deviceId}/changes`),
    ]).then(([value, history]) => { if (active) { setDetail(value); setChanges(history.data) } }).catch(reason => { if (active) setError(reason.message) })
    return () => { active = false }
  }, [deviceId, revision])
  useEffect(() => {
    if (tab !== 'updates') return
    let active = true
    request<{ data: DeviceUpdate[] }>(`/api/admin/console/devices/${deviceId}/updates`)
      .then(value => { if (active) setUpdates(value.data) })
      .catch(reason => { if (active) setError(reason.message) })
    return () => { active = false }
  }, [tab, deviceId, revision])
  useEffect(() => {
    if (!collection || ['completed', 'failed', 'expired'].includes(collection.status)) return
    const timer = window.setInterval(() => {
      request<{ data: { id: string; status: string } }>(`/api/admin/console/context/collections/${collection.id}`)
        .then(value => {
          setCollection(value.data)
          if (value.data.status === 'completed') setRevision(current => current + 1)
        })
        .catch(reason => setRefreshError(reason.message))
    }, 3000)
    return () => window.clearInterval(timer)
  }, [collection])
  async function refreshContext() {
    setRefreshError('')
    try {
      const result = await request<{ data: { id: string; status: string } }>(`/api/admin/console/devices/${deviceId}/context/collections`, {
        method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() },
        body: JSON.stringify({ profile: refreshProfile }),
      })
      setCollection(result.data)
    } catch (reason) { setRefreshError(reason instanceof Error ? reason.message : 'Не удалось запросить Context') }
  }
  if (error) return <LoadError message={error} retry={() => { setError(''); setRevision(value => value + 1) }} />
  if (!detail) return <p aria-live="polite">Загрузка устройства…</p>
  const inventory = detail.snapshots.find(item => item.profile === 'inventory_v1')
  const session = detail.snapshots.find(item => item.profile === 'session_v1')
  return <>
    <Link className="back-link" to="/admin/devices">← Все устройства</Link>
    <div className="page-heading"><div><p className="eyebrow">УСТРОЙСТВО</p><h1>{detail.device.display_name}</h1><p className="muted">{detail.device.device_identifier} · {detail.device.online ? 'В сети' : 'Не в сети'} · Agent {detail.device.agent_version ?? '—'} · Последняя связь: {dateText(detail.device.last_seen_at)}</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <nav className="tabs" aria-label="Разделы устройства">{[['overview', 'Обзор'], ['context', 'Контекст'], ['changes', 'Изменения'], ['operations', 'Операции'], ['updates', 'Обновления'], ['modules', 'Модули'], ['audit', 'Аудит']].map(([key, label]) => <button key={key} className={tab === key ? 'selected' : ''} onClick={() => setTab(key)}>{label}</button>)}</nav>
    {tab === 'modules' && deviceId && <DeviceModules deviceId={deviceId} />}
    {tab === 'overview' && <div className="detail-columns">{inventory ? Object.entries(inventory.sections).map(([name, value]) => <section className="panel" key={name}><h2>{{system:'Система',hardware:'Оборудование',memory:'Память',storage:'Накопители',interfaces:'Сеть'}[name] ?? name}</h2><SectionRows data={typeof value === 'object' && !Array.isArray(value) && value ? value as Record<string, unknown> : { items: value }} /></section>) : <section className="panel"><p>Инвентаризационный Context ещё не получен.</p></section>}{session && <section className="panel"><h2>Сеанс</h2><SectionRows data={session.sections} /></section>}</div>}
    {tab === 'context' && <><div className="panel context-actions"><label>Профиль <select value={refreshProfile} onChange={event => setRefreshProfile(event.target.value)}>{Object.entries(profileLabels).map(([profile, label]) => <option value={profile} key={profile}>{label}</option>)}</select></label><button onClick={refreshContext}>Обновить данные</button>{collection && <span>Сбор: {collectionLabels[collection.status] ?? collection.status}</span>}{refreshError && <span className="error" role="alert">{refreshError}</span>}</div><div className="detail-columns">{Object.entries(profileLabels).map(([profile, label]) => { const snapshot = detail.snapshots.find(item => item.profile === profile); return <section className="panel" key={profile}><h2>{label}</h2>{snapshot ? <><p className="muted">Собрано: {dateText(snapshot.collected_at)}</p><p className="muted">Snapshot: {snapshot.id}</p>{snapshot.warnings.length > 0 && <p className="error">Предупреждения: {snapshot.warnings.join(', ')}</p>}<SectionRows data={snapshot.sections} /></> : <p className="muted">Данные не собраны.</p>}</section> })}</div></>}
    {tab === 'changes' && <section className="panel"><h2>Изменения Context</h2>{changes.length ? <ul className="change-list">{changes.map((item, index) => <li key={`${item.after_snapshot_id}-${item.code}-${index}`}><div><strong>{changeLabels[item.code] ?? 'Изменение'}</strong>{item.before_value !== null && item.after_value !== null && <p>{item.code === 'RAM_CHANGED' ? sizeText(Number(item.before_value)) : item.before_value} → {item.code === 'RAM_CHANGED' ? sizeText(Number(item.after_value)) : item.after_value}</p>}</div><span>{dateText(item.collected_at)} · {profileLabels[item.profile] ?? item.profile}</span></li>)}</ul> : <p className="muted">Изменений пока нет.</p>}</section>}
    {tab === 'updates' && <section className="panel"><h2>История обновлений</h2>{updates === null ? <p>Загрузка…</p> : updates.length ? <ul className="change-list">{updates.map(item => <li key={item.rollout_id}><div><strong><Link to={`/admin/updates?open=${item.rollout_id}`}>{item.version}</Link></strong><p>{updateLabels[item.status] ?? item.status}{item.safe_reason ? ` · ${item.safe_reason}` : ''}</p></div><span>{dateText(item.assigned_at)}</span></li>)}</ul> : <p className="muted">Обновлений пока нет.</p>}<Link to="/admin/updates">Все развёртывания</Link></section>}
    {tab === 'operations' && <section className="panel"><h2>Операции устройства</h2><Link to={`/admin/operations?device_id=${deviceId}`}>Открыть журнал операций устройства</Link></section>}
    {tab === 'audit' && <section className="panel"><h2>Аудит устройства</h2><Link to={`/admin/audit?object_kind=device&object_id=${deviceId}`}>Открыть события устройства</Link></section>}
  </>
}
