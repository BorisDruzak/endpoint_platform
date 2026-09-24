import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { ApiError, request } from './api'

type Operation = {
  operation_id: string; device_id: string; device_name: string; capability: string; status: string
  owner: string; created_at: string; deadline_at: string; completed_at: string | null; duration_ms: number | null
}
type Detail = {
  data: Operation
  safe_result: { collected_at: string; reason: string; warnings: string[]; processes: { name: string; state: string }[]; log_excerpt: string | null } | null
  module_detail: { module_key: string; version: string; steps: { sequence: number; capability: string; status: string; error_code: string | null; safe_result: unknown }[] } | null
  evidence: { result_available: boolean; result_expires_at: string | null; result_pinned: boolean; result_scrubbed_at: string | null; result_digest: string } | null
}
const statusLabels: Record<string, string> = {
  queued: 'В очереди', delivered: 'Доставлено', acknowledged: 'Подтверждено', running: 'Выполняется',
  succeeded: 'Успешно', failed: 'Ошибка', canceled: 'Отменено', expired: 'Истекло',
}
const capabilityLabels: Record<string, string> = {
  'context.diagnostic.collect': 'Сбор диагностики', 'endpoint.module.recipe': 'Запуск модуля',
  'dns.resolve': 'DNS', 'network.ping': 'Ping', 'tcp.connect': 'TCP',
  'route.get': 'Маршрут', 'adapter.list': 'Адаптеры', 'system.service_status': 'Служба',
}
const dateText = (value: string | null) => value ? new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'

export function OperationsPage() {
  const [params, setParams] = useSearchParams()
  const [operations, setOperations] = useState<Operation[]>([])
  const [total, setTotal] = useState(0)
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')
  const [detailId, setDetailId] = useState<string | null>(null)
  const [detail, setDetail] = useState<Detail | null>(null)
  const [revision, setRevision] = useState(0)
  const [busy, setBusy] = useState(false)
  const [pinReason, setPinReason] = useState('')
  const listingParams = new URLSearchParams(params)
  listingParams.delete('open')
  const query = listingParams.toString()
  useEffect(() => { if (params.get('open')) setDetailId(params.get('open')) }, [params])
  const offset = Number(params.get('offset') ?? 0)

  useEffect(() => {
    let active = true
    request<{ data: Operation[]; total: number }>(`/api/admin/operations?limit=50&${query}`)
      .then(value => { if (active) { setOperations(value.data); setTotal(value.total); setLoaded(true); setError('') } })
      .catch(reason => { if (active) { setError(reason instanceof ApiError && reason.status === 404 ? 'Операции отключены на сервере.' : reason.message); setLoaded(true) } })
    return () => { active = false }
  }, [query, revision])
  useEffect(() => {
    if (!detailId) return
    let active = true
    request<Detail>(`/api/admin/operations/${detailId}`)
      .then(value => { if (active) setDetail(value) })
      .catch(reason => { if (active) setError(reason.message) })
    return () => { active = false }
  }, [detailId, revision])
  function filter(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    next.delete('offset'); setParams(next)
  }
  function move(nextOffset: number) { const next = new URLSearchParams(params); next.set('offset', String(nextOffset)); setParams(next) }
  async function cancel() {
    if (!detail || !window.confirm(`Отменить операцию для ${detail.data.device_name}?`)) return
    setBusy(true); setError('')
    try { await request(`/api/admin/operations/${detail.data.operation_id}/cancel`, { method: 'POST' }); setRevision(value => value + 1) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Отменить операцию не удалось') }
    finally { setBusy(false) }
  }
  async function pinEvidence() {
    if (!detail) return
    setBusy(true); setError('')
    try {
      await request(`/api/admin/operations/${detail.data.operation_id}/evidence/pin`, {
        method: 'POST', body: JSON.stringify({ reason: pinReason.trim() || null }),
      })
      setRevision(value => value + 1)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Закрепить результат не удалось') }
    finally { setBusy(false) }
  }
  return <>
    <div className="page-heading"><div><p className="eyebrow">ЖУРНАЛ</p><h1>Операции</h1><p className="muted">Выполнение диагностик и модулей на устройствах</p></div><button onClick={() => setRevision(value => value + 1)}>Обновить</button></div>
    <div className="filters panel"><label>Устройство UUID<input value={params.get('device_id') ?? ''} onChange={event => filter('device_id', event.target.value)} placeholder="Все устройства" /></label><label>Тип<select value={params.get('capability') ?? ''} onChange={event => filter('capability', event.target.value)}><option value="">Все</option>{Object.entries(capabilityLabels).filter(([key]) => key.startsWith('context.') || key.startsWith('endpoint.')).map(([key, value]) => <option key={key} value={key}>{value}</option>)}</select></label><label>Состояние<select value={params.get('operation_status') ?? ''} onChange={event => filter('operation_status', event.target.value)}><option value="">Все</option>{Object.entries(statusLabels).map(([key, value]) => <option key={key} value={key}>{value}</option>)}</select></label><label>С<input type="datetime-local" value={params.get('since')?.slice(0, 16) ?? ''} onChange={event => filter('since', event.target.value ? new Date(event.target.value).toISOString() : '')} /></label><label>По<input type="datetime-local" value={params.get('until')?.slice(0, 16) ?? ''} onChange={event => filter('until', event.target.value ? new Date(event.target.value).toISOString() : '')} /></label></div>
    {error && <section className="panel error" role="alert">{error} <button onClick={() => setRevision(value => value + 1)}>Повторить</button></section>}
    {!loaded && <p aria-live="polite">Загрузка операций…</p>}
    {loaded && !error && <section className="panel table-panel"><div className="table-top"><h2>Журнал операций</h2><span>{total} всего</span></div>{operations.length ? <div className="table-scroll"><table><thead><tr><th>Создано</th><th>Устройство</th><th>Тип</th><th>Состояние</th><th>Источник</th><th>Длительность</th><th>Завершено</th><th></th></tr></thead><tbody>{operations.map(item => <tr key={item.operation_id}><td>{dateText(item.created_at)}</td><td><Link to={`/admin/devices/${item.device_id}`}>{item.device_name}</Link></td><td>{capabilityLabels[item.capability] ?? item.capability}</td><td>{statusLabels[item.status] ?? item.status}</td><td>{item.owner}</td><td>{item.duration_ms === null ? '—' : `${(item.duration_ms / 1000).toFixed(1)} с`}</td><td>{dateText(item.completed_at)}</td><td><button onClick={() => { setDetail(null); setDetailId(item.operation_id) }}>Открыть</button></td></tr>)}</tbody></table></div> : <p className="empty-text">Операций по заданным условиям нет.</p>}<div className="pagination"><button disabled={offset === 0} onClick={() => move(Math.max(0, offset - 50))}>Назад</button><span>{Math.min(offset + 50, total)} из {total}</span><button disabled={offset + 50 >= total} onClick={() => move(offset + 50)}>Далее</button></div></section>}
    {detailId && <div className="dialog-backdrop" role="presentation" onClick={() => { setDetailId(null); setDetail(null) }}><section className="dialog panel rollout-dialog" role="dialog" aria-modal="true" aria-label="Операция" onClick={event => event.stopPropagation()}><button className="dialog-close" onClick={() => { setDetailId(null); setDetail(null) }}>Закрыть</button>{detail ? <><h2>{capabilityLabels[detail.data.capability] ?? detail.data.capability}</h2><p>{statusLabels[detail.data.status] ?? detail.data.status}</p><dl className="simple-facts"><dt>Устройство</dt><dd><Link to={`/admin/devices/${detail.data.device_id}`}>{detail.data.device_name}</Link></dd><dt>Источник</dt><dd>{detail.data.owner}</dd><dt>Создано</dt><dd>{dateText(detail.data.created_at)}</dd><dt>Завершено</dt><dd>{dateText(detail.data.completed_at)}</dd><dt>Срок</dt><dd>{dateText(detail.data.deadline_at)}</dd></dl>{detail.data.status === 'queued' && detail.data.capability === 'context.diagnostic.collect' && <button disabled={busy} onClick={cancel}>Отменить операцию</button>}{detail.evidence && <section><h3>Результат операции</h3>{detail.evidence.result_pinned ? <p>Результат закреплён · Обычный срок хранения не применяется</p> : detail.evidence.result_available ? <p>Результат доступен до: {dateText(detail.evidence.result_expires_at)}</p> : <p>Результат удалён по политике хранения</p>}<p>SHA-256 результата: {detail.evidence.result_digest}</p>{detail.evidence.result_available && !detail.evidence.result_pinned && <><label>Причина закрепления<input maxLength={256} value={pinReason} onChange={event => setPinReason(event.target.value)} /></label><button disabled={busy} onClick={pinEvidence}>Закрепить результат</button></>}</section>}{detail.safe_result && <section><h3>Безопасный результат диагностики</h3><p>Собрано: {dateText(detail.safe_result.collected_at)}</p><p>Причина: {detail.safe_result.reason}</p><ul>{detail.safe_result.processes.map((item, index) => <li key={index}>{item.name} · {item.state}</li>)}</ul>{detail.safe_result.log_excerpt && <pre className="safe-log">{detail.safe_result.log_excerpt}</pre>}</section>}{detail.module_detail && <section><h3>{detail.module_detail.module_key}@{detail.module_detail.version}</h3><ol className="module-steps">{detail.module_detail.steps.map(step => <li key={step.sequence}><strong>{capabilityLabels[step.capability] ?? step.capability}</strong><span>{statusLabels[step.status] ?? step.status}{step.error_code ? ` · ${step.error_code}` : ''}</span>{step.safe_result != null && <pre className="safe-log">{JSON.stringify(step.safe_result, null, 2)}</pre>}</li>)}</ol></section>}</> : <p>Загрузка операции…</p>}</section></div>}
  </>
}
