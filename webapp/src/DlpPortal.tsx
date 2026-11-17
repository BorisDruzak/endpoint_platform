import { useEffect, useState } from 'react'
import type { EmployeeRequest } from './employeeApi'

type DlpEvent = { id: string; device_id: string; device_name: string; event_type: string; occurred_at: string; channel: string; user_login: string | null; policy_version: number; domain: string | null }
type DlpDetail = DlpEvent & { safe_metadata: Record<string, string | number | boolean | string[] | null>; metadata_valid: boolean }
type Policy = { id: string; name: string; created_at: string; versions_total: number }
type PolicyVersion = { version_id: string; policy_version: number; digest: string; created_at: string }
type DlpMode = 'audit' | 'disabled'
type PolicyContent = PolicyVersion & { policy: { schema_version: 'endpoint_policy_v1'; policy_id: string; policy_version: number; dlp: { usb_device_events: DlpMode; removable_write_events: DlpMode; print_events: DlpMode; browser_upload_events: DlpMode; browser_paste_events: DlpMode }; browser_sensor: { required: boolean; deployment_mode: string }; event_retention: { security_event_days: number } } }
type Sensor = { device_id: string; device_name: string; observed_at: string | null; activity_listener_state: string | null; security_spool_state: string | null; usb_source_state: string | null; print_source_state: string | null }
type Page<T> = { data: T[]; total: number; offset: number; limit: number }
const labels: Record<string, string> = { USB_DEVICE_CONNECTED: 'USB-устройство подключено', USB_DEVICE_DISCONNECTED: 'USB-устройство отключено', PRINT_JOB: 'Печать', BROWSER_UPLOAD: 'Передача файла через браузер', BROWSER_PASTE: 'Вставка в браузере' }
const timestamp = (value: string | null) => value ? new Intl.DateTimeFormat('ru-RU', { timeZone: 'Asia/Yekaterinburg', dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)) : 'Нет данных'

export function DlpPortal({ request }: { request: EmployeeRequest }) {
  const [section, setSection] = useState<'events' | 'policies' | 'sensors'>('events')
  const [channel, setChannel] = useState(''), [revision, setRevision] = useState(0), [offset, setOffset] = useState(0)
  const [events, setEvents] = useState<Page<DlpEvent> | null>(null), [policies, setPolicies] = useState<Page<Policy> | null>(null), [sensors, setSensors] = useState<Page<Sensor> | null>(null)
  const [selected, setSelected] = useState(''), [detail, setDetail] = useState<DlpDetail | null>(null)
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [error, setError] = useState(''), [detailError, setDetailError] = useState('')
  useEffect(() => {
    let active = true
    setEvents(null); setPolicies(null); setSensors(null); setError(''); setSelected(''); setDetail(null); setSelectedPolicy(null)
    const query = `?limit=50&offset=${offset}${channel && section === 'events' ? `&channel=${channel}` : ''}`
    const load = section === 'events' ? request<Page<DlpEvent>>(`/api/dlp/events${query}`).then(value => { if (active) setEvents(value) })
      : section === 'policies' ? request<Page<Policy>>(`/api/dlp/policies${query}`).then(value => { if (active) setPolicies(value) })
        : request<Page<Sensor>>(`/api/dlp/sensors${query}`).then(value => { if (active) setSensors(value) })
    load.catch(reason => { if (active && reason?.name !== 'AbortError') setError(reason instanceof Error ? reason.message : 'Не удалось загрузить раздел DLP.') })
    return () => { active = false }
  }, [request, section, channel, offset, revision])
  useEffect(() => {
    if (!selected) return
    let active = true
    setDetail(null); setDetailError('')
    request<{ data: DlpDetail }>(`/api/dlp/events/${encodeURIComponent(selected)}`).then(value => { if (active) setDetail(value.data) }).catch(reason => { if (active && reason?.name !== 'AbortError') setDetailError(reason instanceof Error ? reason.message : 'Не удалось загрузить событие.') })
    return () => { active = false }
  }, [request, selected])
  const page = events ?? policies ?? sensors
  return <><div className="page-heading"><div><p className="eyebrow">DLP</p><h1>События безопасности</h1><p className="muted">USB, печать, браузер и политики · Отдельное полномочие DLP Officer</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить события</button></div>
    <nav className="wt-status-actions wt-dlp-tabs" aria-label="Разделы DLP">{([['events', 'История событий'], ['policies', 'Политики'], ['sensors', 'Состояние сенсоров']] as const).map(([code, title]) => <button key={code} aria-pressed={section === code} onClick={() => { setSection(code); setOffset(0) }}>{title}</button>)}</nav>
    {section === 'events' && <section className="panel wt-toolbar"><label>Канал DLP<select value={channel} onChange={event => { setChannel(event.target.value); setOffset(0) }}><option value="">Все каналы</option><option value="USB">USB</option><option value="PRINT">Печать</option><option value="BROWSER">Браузер</option></select></label></section>}
    {error ? <section className="panel"><p className="error" role="alert">{error}</p><button onClick={() => setRevision(value => value + 1)}>Повторить</button></section> : !page ? <p aria-live="polite">Загрузка DLP…</p> : <section className="panel"><h2>{section === 'events' ? 'История событий' : section === 'policies' ? 'Политики' : 'Состояние сенсоров'}</h2>
      {page.total === 0 && <p className="muted">Записей нет.</p>}
      {events && <ul className="wt-list">{events.data.map(item => <li key={item.id}><button onClick={() => setSelected(item.id)}>{timestamp(item.occurred_at)} · {item.device_name} · {labels[item.event_type] ?? item.event_type}</button><p className="muted">{item.channel} · {item.user_login ?? 'Пользователь не установлен'} · Политика {item.policy_version}</p></li>)}</ul>}
      {policies && <ul className="wt-list">{policies.data.map(item => <li key={item.id}><strong>{item.name}</strong><p className="muted">Версий: {item.versions_total} · Создана {timestamp(item.created_at)}</p><button onClick={() => setSelectedPolicy(item)}>Версии политики {item.name}</button></li>)}</ul>}
      {sensors && <div className="table-scroll"><table className="wt-report"><thead><tr><th>Устройство</th><th>Наблюдение</th><th>USB</th><th>Печать</th><th>Очередь событий</th><th>Слушатель</th></tr></thead><tbody>{sensors.data.map(item => <tr key={item.device_id}><td>{item.device_name}</td><td>{timestamp(item.observed_at)}</td><td>{item.usb_source_state ?? 'Нет данных'}</td><td>{item.print_source_state ?? 'Нет данных'}</td><td>{item.security_spool_state ?? 'Нет данных'}</td><td>{item.activity_listener_state ?? 'Нет данных'}</td></tr>)}</tbody></table></div>}
      <div className="pagination"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Предыдущие</button><span>{Math.min(offset + 50, page.total)} из {page.total}</span><button disabled={offset + 50 >= page.total} onClick={() => setOffset(offset + 50)}>Следующие</button></div>
    </section>}
    {selectedPolicy && section === 'policies' && <PolicyHistory key={selectedPolicy.id} policy={selectedPolicy} request={request} />}
    {selected && <section className="panel wt-selection" aria-label="Детали события DLP"><div className="wt-card-heading"><h2>Детали события</h2><button onClick={() => { setSelected(''); setDetail(null) }}>Закрыть детали</button></div>{detailError ? <p role="alert">{detailError}</p> : !detail ? <p aria-live="polite">Загрузка деталей…</p> : <><p>{labels[detail.event_type] ?? detail.event_type} · {timestamp(detail.occurred_at)}</p><p>{detail.device_name} · {detail.domain ?? 'Домен не указан'}</p><dl className="wt-summary">{Object.entries(detail.safe_metadata).map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value === null ? 'Нет данных' : Array.isArray(value) ? value.join(', ') : typeof value === 'boolean' ? value ? 'Да' : 'Нет' : String(value)}</dd></div>)}</dl>{!detail.metadata_valid && <p className="muted">Метаданные недоступны.</p>}</>}</section>}
  </>
}

function PolicyHistory({ policy, request }: { policy: Policy; request: EmployeeRequest }) {
  const [page, setPage] = useState<Page<PolicyVersion> | null>(null), [offset, setOffset] = useState(0), [revision, setRevision] = useState(0)
  const [selected, setSelected] = useState(''), [detail, setDetail] = useState<PolicyContent | null>(null)
  const [error, setError] = useState(''), [detailError, setDetailError] = useState('')
  const path = `/api/dlp/policies/${encodeURIComponent(policy.id)}/versions`
  useEffect(() => {
    let active = true
    setPage(null); setError(''); setSelected(''); setDetail(null)
    request<Page<PolicyVersion>>(`${path}?limit=50&offset=${offset}`).then(value => { if (active) setPage(value) }).catch(reason => { if (active && reason?.name !== 'AbortError') setError(reason instanceof Error ? reason.message : 'Не удалось загрузить версии политики.') })
    return () => { active = false }
  }, [request, path, offset, revision])
  useEffect(() => {
    setDetail(null); setDetailError('')
    if (!selected) return
    let active = true
    request<{ data: PolicyContent }>(`${path}/${encodeURIComponent(selected)}`).then(value => { if (active) setDetail(value.data) }).catch(reason => { if (active && reason?.name !== 'AbortError') setDetailError(reason instanceof Error ? reason.message : 'Не удалось загрузить содержимое политики.') })
    return () => { active = false }
  }, [request, path, selected])
  return <section className="panel wt-selection" aria-label="История политики DLP"><h2>История политики {policy.name}</h2>{error ? <><p role="alert" className="error">{error}</p><button onClick={() => setRevision(value => value + 1)}>Повторить загрузку версий</button></> : !page ? <p aria-live="polite">Загрузка версий…</p> : <><ul className="wt-list">{page.data.map(item => <li key={item.version_id}><button aria-pressed={selected === item.version_id} onClick={() => setSelected(item.version_id)}>Версия политики {item.policy_version} · {timestamp(item.created_at)}</button></li>)}</ul>{!page.total && <p className="muted">Опубликованных версий нет.</p>}<div className="pagination"><button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>Предыдущие версии</button><span>{Math.min(offset + 50, page.total)} из {page.total}</span><button disabled={offset + 50 >= page.total} onClick={() => setOffset(offset + 50)}>Следующие версии</button></div></>}
    {detailError && <p role="alert" className="error">{detailError}</p>}{selected && !detail && !detailError && <p aria-live="polite">Загрузка содержимого версии…</p>}
    {detail && <section aria-label="Содержимое политики DLP"><h3>Настройки DLP · Версия {detail.policy_version}</h3><dl className="wt-summary">{([['usb_device_events', 'События USB'], ['removable_write_events', 'Запись на съёмный носитель'], ['print_events', 'Печать'], ['browser_upload_events', 'Передача файлов в браузере'], ['browser_paste_events', 'Вставка в браузере']] as const).map(([code, title]) => <div key={code}><dt>{title}</dt><dd>{detail.policy.dlp[code] === 'audit' ? 'Включено' : detail.policy.dlp[code] === 'disabled' ? 'Отключено' : 'Неизвестный режим'}</dd></div>)}<div><dt>Сенсор браузера обязателен</dt><dd>{detail.policy.browser_sensor.required ? 'Да' : 'Нет'}</dd></div><div><dt>Режим сенсора браузера</dt><dd>{detail.policy.browser_sensor.deployment_mode}</dd></div><div><dt>Хранение событий безопасности</dt><dd>{detail.policy.event_retention.security_event_days} дней</dd></div></dl><p className="muted wt-small">Контрольная сумма версии: {detail.digest}</p></section>}
  </section>
}
