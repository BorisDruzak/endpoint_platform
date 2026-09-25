import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { ApiError, request } from './api'
import { PolicyCatalog } from './PolicyCatalog'
import { BrowserReleaseStatus } from './BrowserReleaseStatus'

type EventType = 'USB_DEVICE_CONNECTED' | 'USB_DEVICE_DISCONNECTED' | 'PRINT_JOB' | 'BROWSER_UPLOAD' | 'BROWSER_PASTE'
type SecurityEvent = {
  id: string; device_id: string; device_name: string; event_type: EventType
  channel: 'USB' | 'PRINT' | 'BROWSER'; severity: 'INFO'
  occurred_at: string; received_at: string; user_login: string | null
  policy_id: string; policy_version: number; domain: string | null; metadata_valid: boolean
}
type EventDetail = SecurityEvent & { safe_metadata: Record<string, string | number | boolean | string[] | null> }
type Page = { data: SecurityEvent[]; total: number; limit: number; offset: number }

const eventLabels: Record<EventType, string> = {
  USB_DEVICE_CONNECTED: 'USB-устройство подключено',
  USB_DEVICE_DISCONNECTED: 'USB-устройство отключено',
  PRINT_JOB: 'Печать',
  BROWSER_UPLOAD: 'Передача файла через браузер',
  BROWSER_PASTE: 'Вставка в браузере',
}
const channelLabels: Record<SecurityEvent['channel'], string> = {
  USB: 'USB', PRINT: 'Печать', BROWSER: 'Браузер',
}
const metadataLabels: Record<string, string> = {
  vendor: 'Производитель', product: 'Устройство', device_class: 'Класс',
  removable: 'Съёмное', serial_hash: 'Хеш серийного номера',
  printer_identity: 'Принтер', page_count: 'Страниц', copies: 'Копий',
  total_bytes: 'Размер, байт', domain: 'Домен', origin: 'Источник',
  browser_family: 'Браузер', file_count: 'Файлов',
  mime_categories: 'Категории файлов', clipboard_types: 'Типы данных',
}
const categoryLabels: Record<string, string> = {
  spreadsheet: 'Таблица', document: 'Документ', image: 'Изображение',
  video: 'Видео', audio: 'Аудио', archive: 'Архив', other: 'Другое',
  text: 'Текст', html: 'HTML', files: 'Файлы',
  chrome: 'Chrome', yandex: 'Яндекс Браузер',
  mass_storage: 'Накопитель', hid: 'Устройство ввода', printer: 'Принтер',
}
const dateText = (value: string) => new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
const metadataText = (value: string | number | boolean | string[] | null) => {
  if (value === null) return 'Нет данных'
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет'
  if (Array.isArray(value)) return value.map(item => categoryLabels[item] ?? item).join(', ') || 'Нет данных'
  return typeof value === 'string' ? categoryLabels[value] ?? value : String(value)
}

export function SecurityPage() {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState<Page | null>(null)
  const [detail, setDetail] = useState<EventDetail | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [detailError, setDetailError] = useState('')
  const [revision, setRevision] = useState(0)
  const query = params.toString()

  useEffect(() => {
    let active = true
    request<Page>(`/api/admin/console/security/events?limit=50&${query}`)
      .then(value => { if (active) { setPage(value); setError('') } })
      .catch(reason => { if (active) setError(reason instanceof ApiError && reason.status === 404
        ? 'Раздел «Политики и DLP» сейчас отключён'
        : reason instanceof Error ? reason.message : 'Не удалось загрузить события безопасности') })
    return () => { active = false }
  }, [query, revision])
  useEffect(() => {
    if (!selected) return
    let active = true
    request<{ data: EventDetail }>(`/api/admin/console/security/events/${selected}`)
      .then(value => { if (active) { setDetail(value.data); setDetailError('') } })
      .catch(reason => { if (active) setDetailError(reason instanceof Error ? reason.message : 'Не удалось загрузить событие') })
    return () => { active = false }
  }, [selected, revision])

  function filter(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    next.delete('offset')
    setSelected(null); setDetail(null); setPage(null); setParams(next)
  }
  function move(offset: number) {
    const next = new URLSearchParams(params)
    next.set('offset', String(offset))
    setSelected(null); setDetail(null); setPage(null); setParams(next)
  }
  function select(id: string) { setSelected(id); setDetail(null); setDetailError('') }
  const offset = Number(params.get('offset') ?? 0)

  return <>
    <div className="page-heading"><div><p className="eyebrow">ПОЛИТИКИ И DLP</p><h1>События безопасности</h1><p className="muted">События аудита USB, печати и действий в браузере</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <PolicyCatalog />
    <BrowserReleaseStatus key={revision} />
    <div className="filters panel">
      <label>С<input type="datetime-local" value={params.get('since')?.slice(0, 16) ?? ''} onChange={event => filter('since', event.target.value ? new Date(event.target.value).toISOString() : '')} /></label>
      <label>По<input type="datetime-local" value={params.get('until')?.slice(0, 16) ?? ''} onChange={event => filter('until', event.target.value ? new Date(event.target.value).toISOString() : '')} /></label>
      <label>ID устройства<input value={params.get('device_id') ?? ''} onChange={event => filter('device_id', event.target.value)} placeholder="UUID устройства" /></label>
      <label>Пользователь<input value={params.get('user_login') ?? ''} onChange={event => filter('user_login', event.target.value)} /></label>
      <label>Канал<select value={params.get('channel') ?? ''} onChange={event => filter('channel', event.target.value)}><option value="">Все</option><option value="USB">USB</option><option value="PRINT">Печать</option><option value="BROWSER">Браузер</option></select></label>
      <label>Событие<select value={params.get('event_type') ?? ''} onChange={event => filter('event_type', event.target.value)}><option value="">Все</option>{Object.entries(eventLabels).map(([code, title]) => <option key={code} value={code}>{title}</option>)}</select></label>
      <label>Важность<select value={params.get('severity') ?? ''} onChange={event => filter('severity', event.target.value)}><option value="">Все</option><option value="INFO">Информация</option></select></label>
      <label>Домен<input value={params.get('domain') ?? ''} onChange={event => filter('domain', event.target.value)} placeholder="example.org" /></label>
    </div>
    {error && <section className="panel error" role="alert">{error} <button onClick={() => setRevision(value => value + 1)}>Повторить</button></section>}
    {!page && !error && <p aria-live="polite">Загрузка событий…</p>}
    {page && !error && <section className="panel table-panel"><div className="table-top"><h2>События</h2><span>{page.total.toLocaleString('ru-RU')} всего</span></div>
      {page.data.length ? <div className="table-scroll"><table><thead><tr><th>Время</th><th>Устройство</th><th>Пользователь</th><th>Канал</th><th>Событие</th><th>Назначение</th><th>Политика</th><th></th></tr></thead><tbody>{page.data.map(item => <tr key={item.id}><td>{dateText(item.occurred_at)}</td><td><Link to={`/admin/devices/${item.device_id}`}>{item.device_name}</Link></td><td>{item.user_login ?? 'Нет данных'}</td><td>{channelLabels[item.channel]}</td><td>{eventLabels[item.event_type]}</td><td>{item.domain ?? '—'}</td><td>Версия {item.policy_version}</td><td><button onClick={() => select(item.id)}>Детали</button></td></tr>)}</tbody></table></div> : <p className="empty-text">Событий по заданным условиям нет.</p>}
      <div className="pagination"><button disabled={offset === 0} onClick={() => move(Math.max(0, offset - 50))}>Назад</button><span>{Math.min(offset + 50, page.total)} из {page.total}</span><button disabled={offset + 50 >= page.total} onClick={() => move(offset + 50)}>Далее</button></div>
    </section>}
    {selected && <section className="panel" aria-label="Детали события"><div className="table-top"><h2>Детали события</h2><button onClick={() => { setSelected(null); setDetail(null) }}>Закрыть</button></div>
      {detailError ? <p role="alert">{detailError}</p> : !detail ? <p aria-live="polite">Загрузка деталей…</p> : <><h3>{eventLabels[detail.event_type]}</h3><dl className="detail-grid">
        <div><dt>Устройство</dt><dd>{detail.device_name}</dd></div><div><dt>Пользователь</dt><dd>{detail.user_login ?? 'Нет данных'}</dd></div>
        <div><dt>Время</dt><dd>{dateText(detail.occurred_at)}</dd></div><div><dt>Политика</dt><dd>Версия {detail.policy_version}</dd></div><div><dt>Режим</dt><dd>Аудит</dd></div>
        {Object.entries(detail.safe_metadata).filter(([key]) => metadataLabels[key]).map(([key, value]) => <div key={key}><dt>{metadataLabels[key]}</dt><dd>{metadataText(value)}</dd></div>)}
      </dl>{!detail.metadata_valid && <p className="muted">Метаданные события недоступны.</p>}</>}
    </section>}
  </>
}
