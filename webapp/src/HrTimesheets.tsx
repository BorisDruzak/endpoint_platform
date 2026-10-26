import { useEffect, useRef, useState } from 'react'
import { worktimePath, type EmployeeRequest, type WorkDay } from './employeeApi'
import { durationText } from './WorkTimeRing'

type TimesheetVersion = { id: string; person_id: string; month: string; version: number; timezone: string; finalized_by: string; finalized_at: string; reason: string; source_digest: string; totals: WorkDay['totals'] }
type Timesheet = TimesheetVersion & { days: { day: string; totals: WorkDay['totals']; corrections: unknown[]; approvals: unknown[] }[] }
const text = (reason: unknown) => reason instanceof Error ? reason.message : 'Не удалось загрузить табели.'
const reportMonth = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Yekaterinburg', year: 'numeric', month: '2-digit' }).format(new Date())
const dateTime = (value: string) => new Intl.DateTimeFormat('ru-RU', { timeZone: 'Asia/Yekaterinburg', dateStyle: 'short', timeStyle: 'short' }).format(new Date(value))

export function HrTimesheets({ request, personId, month }: { request: EmployeeRequest; personId: string; month: string }) {
  const [versions, setVersions] = useState<TimesheetVersion[] | null>(null), [revision, setRevision] = useState(0)
  const [selected, setSelected] = useState(''), [snapshot, setSnapshot] = useState<Timesheet | null>(null)
  const [reason, setReason] = useState(''), [busy, setBusy] = useState(false), [error, setError] = useState(''), [detailError, setDetailError] = useState(''), [notice, setNotice] = useState('')
  const retry = useRef<{ signature: string; id: string } | null>(null), writing = useRef(false)
  const closed = month < reportMonth()
  useEffect(() => {
    let active = true
    setVersions(null); setError('')
    request<{ timesheets: TimesheetVersion[] }>(`${worktimePath}/timesheets?month=${month}&person_id=${encodeURIComponent(personId)}`).then(value => {
      if (!active) return
      if (value.timesheets.some(item => item.person_id !== personId || item.month !== month)) throw new Error('Ответ не соответствует выбранному сотруднику или месяцу.')
      setVersions(value.timesheets)
    }).catch(reason => { if (active && reason?.name !== 'AbortError') setError(text(reason)) })
    return () => { active = false }
  }, [request, personId, month, revision])
  useEffect(() => {
    setSnapshot(null); setDetailError('')
    if (!selected) return
    let active = true
    request<Timesheet>(`${worktimePath}/timesheets/${encodeURIComponent(selected)}`).then(value => {
      if (!active) return
      if (value.person_id !== personId || value.month !== month) throw new Error('Табель не соответствует выбранному сотруднику или месяцу.')
      setSnapshot(value)
    }).catch(reason => { if (active && reason?.name !== 'AbortError') setDetailError(text(reason)) })
    return () => { active = false }
  }, [request, selected, personId, month])
  async function finalize() {
    if (writing.current || !closed || !reason.trim()) return
    const payload = { month, reason: reason.trim() }, signature = JSON.stringify(payload)
    if (retry.current?.signature !== signature) retry.current = { signature, id: crypto.randomUUID() }
    writing.current = true; setBusy(true); setError(''); setNotice('')
    try {
      const value = await request<Timesheet>(`${worktimePath}/people/${encodeURIComponent(personId)}/timesheets/finalize`, { method: 'POST', body: JSON.stringify({ ...payload, idempotency_key: retry.current.id }) })
      retry.current = null; setSelected(value.id); setRevision(value => value + 1); setNotice('Новая версия табеля зафиксирована. Предыдущие версии сохранены.')
    } catch (reason) { if (!(reason instanceof Error && reason.name === 'AbortError')) setError(text(reason)) }
    finally { writing.current = false; setBusy(false) }
  }
  return <section className="panel wt-timesheets"><h2>Сохранённые версии табеля</h2><p className="muted wt-small">Зафиксируйте закрытый месяц после согласования корректировок. Последующие исправления требуют новой версии; уже сохранённый табель не изменяется.</p>
    <label>Основание фиксации табеля<textarea value={reason} onChange={event => setReason(event.target.value)} maxLength={2000} rows={2} /></label><p><button disabled={busy || !closed || !reason.trim()} onClick={() => void finalize()}>Зафиксировать новую версию табеля</button></p>{!closed && <p className="muted wt-small">Фиксация доступна после окончания календарного месяца.</p>}
    {notice && <p role="status" className="wt-notice">{notice}</p>}{error && <p role="alert" className="error">{error}</p>}
    {!versions && !error ? <p aria-live="polite">Загрузка сохранённых версий…</p> : versions?.length ? <ul className="wt-list">{versions.map(item => <li key={item.id}><button aria-pressed={selected === item.id} onClick={() => setSelected(item.id)}>Версия {item.version} · {dateTime(item.finalized_at)}</button><p>{item.reason} · Подтверждено {durationText(item.totals.work_seconds)}</p></li>)}</ul> : versions && <p className="muted">Зафиксированных версий ещё нет.</p>}
    {detailError && <p className="error" role="alert">{detailError}</p>}{selected && !snapshot && !detailError && <p aria-live="polite">Загрузка версии…</p>}
    {snapshot && <section aria-label="Сохранённая версия табеля"><h3>Табель {snapshot.month} · Версия {snapshot.version}</h3><p>Зафиксирован {dateTime(snapshot.finalized_at)} · {snapshot.reason}</p><a href={`${worktimePath}/timesheets/${encodeURIComponent(snapshot.id)}/export`} download>Скачать зафиксированный табель CSV</a><div className="table-scroll"><table className="wt-report"><thead><tr><th>Дата</th><th>Подтверждено</th><th>Перерыв</th><th>Вне ПК</th><th>График</th><th>Решения</th></tr></thead><tbody>{snapshot.days.map(day => <tr key={day.day}><td>{day.day}</td><td>{durationText(day.totals.work_seconds)}</td><td>{durationText(day.totals.break_seconds)}</td><td>{durationText(day.totals.off_pc_seconds)}</td><td>{durationText(day.totals.scheduled_seconds)}</td><td>{day.approvals.length}</td></tr>)}</tbody></table></div></section>}
  </section>
}
