import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { request } from './api'

type Event = {
  id: string; created_at: string; actor_kind: string; actor_identifier: string | null
  action: string; object_kind: string; object_identifier: string | null
  request_id: string; details: Record<string, unknown>
}
type Page = { data: Event[]; total: number; limit: number; offset: number }
const dateText = (value: string) => new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
const objectLabels: Record<string, string> = {
  device: 'Устройство', endpoint_operation: 'Операция', update_rollout: 'Развёртывание',
  enrollment_request: 'Запрос регистрации', module_version: 'Версия модуля',
  enrollment_campaign: 'Кампания', context_collection: 'Сбор Context',
}
function objectLink(item: Event) {
  if (!item.object_identifier) return null
  if (item.object_kind === 'device') return `/admin/devices/${item.object_identifier}`
  if (item.object_kind === 'endpoint_operation') return `/admin/operations?open=${encodeURIComponent(item.object_identifier)}`
  if (item.object_kind === 'update_rollout') return `/admin/updates?open=${encodeURIComponent(item.object_identifier)}`
  if (item.object_kind === 'enrollment_request') return `/admin/enrollment?open=${encodeURIComponent(item.object_identifier)}`
  if (item.object_kind === 'module_version' && typeof item.details.module_key === 'string' && typeof item.details.version === 'string') {
    return `/admin/modules?module_key=${encodeURIComponent(item.details.module_key)}&version=${encodeURIComponent(item.details.version)}`
  }
  return null
}

export function AuditPage() {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState<Page | null>(null)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  const [expanded, setExpanded] = useState<string | null>(null)
  const query = params.toString()
  useEffect(() => {
    let active = true
    request<Page>(`/api/admin/audit/events?limit=50&${query}`)
      .then(value => { if (active) { setPage(value); setError('') } })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : 'Не удалось загрузить аудит') })
    return () => { active = false }
  }, [query, revision])
  function filter(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    next.delete('offset'); setParams(next)
  }
  function move(offset: number) { const next = new URLSearchParams(params); next.set('offset', String(offset)); setParams(next) }
  const offset = Number(params.get('offset') ?? 0)
  return <>
    <div className="page-heading"><div><p className="eyebrow">ЖУРНАЛ</p><h1>Аудит</h1><p className="muted">Неизменяемые события административных действий</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <div className="filters panel"><label>С<input type="datetime-local" value={params.get('since')?.slice(0, 16) ?? ''} onChange={event => filter('since', event.target.value ? new Date(event.target.value).toISOString() : '')} /></label><label>По<input type="datetime-local" value={params.get('until')?.slice(0, 16) ?? ''} onChange={event => filter('until', event.target.value ? new Date(event.target.value).toISOString() : '')} /></label><label>Actor<input value={params.get('actor') ?? ''} onChange={event => filter('actor', event.target.value)} placeholder="Тип или ID" /></label><label>Action<input value={params.get('action') ?? ''} onChange={event => filter('action', event.target.value)} /></label><label>Тип объекта<input value={params.get('object_kind') ?? ''} onChange={event => filter('object_kind', event.target.value)} /></label><label>ID объекта<input value={params.get('object_id') ?? ''} onChange={event => filter('object_id', event.target.value)} /></label><label>Request ID<input value={params.get('request_id') ?? ''} onChange={event => filter('request_id', event.target.value)} /></label></div>
    {error && <section className="panel error" role="alert">{error} <button onClick={() => setRevision(value => value + 1)}>Повторить</button></section>}
    {!page && !error && <p aria-live="polite">Загрузка аудита…</p>}
    {page && !error && <section className="panel table-panel"><div className="table-top"><h2>События</h2><span>{page.total} всего</span></div>{page.data.length ? <div className="table-scroll"><table><thead><tr><th>Время</th><th>Actor</th><th>Действие</th><th>Объект</th><th>Request ID</th><th></th></tr></thead><tbody>{page.data.map(item => { const href = objectLink(item); return <tr key={item.id}><td>{dateText(item.created_at)}</td><td>{item.actor_kind}<small>{item.actor_identifier ?? '—'}</small></td><td>{item.action}</td><td>{objectLabels[item.object_kind] ?? item.object_kind}<small>{href ? <Link to={href}>{item.object_identifier}</Link> : item.object_identifier ?? '—'}</small></td><td>{item.request_id}</td><td><button onClick={() => setExpanded(expanded === item.id ? null : item.id)}>{expanded === item.id ? 'Скрыть' : 'Детали'}</button>{expanded === item.id && <pre className="safe-log">{JSON.stringify(item.details, null, 2)}</pre>}</td></tr> })}</tbody></table></div> : <p className="empty-text">Событий по фильтрам нет.</p>}<div className="pagination"><button disabled={offset === 0} onClick={() => move(Math.max(0, offset - 50))}>Назад</button><span>{Math.min(offset + 50, page.total)} из {page.total}</span><button disabled={offset + 50 >= page.total} onClick={() => move(offset + 50)}>Далее</button></div></section>}
  </>
}
