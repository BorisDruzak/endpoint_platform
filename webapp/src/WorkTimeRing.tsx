import { Fragment } from 'react'
import type { ActivityInterval, Category, ExplanationRequest, WorkDay } from './employeeApi'

export const statusLabels: Record<string, string> = { WORKING: 'Работа', BREAK: 'Перерыв', OFF_PC: 'Работа вне ПК', ENDED: 'День завершён', NOT_STARTED: 'День не начат', UNEXPLAINED: 'Требует объяснения', ACTIVE: 'Активен', IDLE: 'Нет ввода', LOCKED: 'Заблокирован', DISCONNECTED: 'Нет соединения', UNKNOWN: 'Нет достоверных данных' }
export const statusColors: Record<string, string> = { WORKING: '#217962', BREAK: '#c18b19', OFF_PC: '#386ab1', ENDED: '#7e8b9d', ACTIVE: '#278672', IDLE: '#b88922', LOCKED: '#8172b3', DISCONNECTED: '#6b8298', UNKNOWN: '#acb6c3' }
export type SelectedInterval = { kind: 'work' | 'activity'; started_at: string; ended_at: string; status: string; source: string; attributed?: boolean; request_id?: string; request?: ExplanationRequest; annotation?: { state: 'explained' | 'pending'; label: string; source: string } }
export const durationText = (seconds: number) => `${Math.floor(seconds / 3600)} ч ${String(Math.floor(seconds % 3600 / 60)).padStart(2, '0')} мин`
export const timeText = (value: string, timezone = 'Asia/Yekaterinburg') => new Intl.DateTimeFormat('ru-RU', { timeZone: timezone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(new Date(value))
export const dayStart = (day: string) => Date.parse(`${day}T00:00:00+05:00`)
/** Slice the status ledger at annotation boundaries; never recalculate confirmed time from explanations. */
export function selectableIntervals(day: WorkDay, categories: Category[] = []): SelectedInterval[] {
  const dayFrom = dayStart(day.day), dayUntil = dayFrom + 86400000
  const annotations = [...day.explanations, ...day.pending_explanations]
  const work: SelectedInterval[] = day.work_intervals.flatMap(item => {
    const from = Math.max(dayFrom, Date.parse(item.started_at)), until = Math.min(dayUntil, Date.parse(item.ended_at))
    if (!Number.isFinite(from) || !Number.isFinite(until) || until <= from) return []
    const cuts = new Set([from, until])
    for (const annotation of annotations) {
      const a = Math.max(from, Date.parse(annotation.started_at)), b = Math.min(until, Date.parse(annotation.ended_at))
      if (Number.isFinite(a) && Number.isFinite(b) && a < b) { cuts.add(a); cuts.add(b) }
    }
    const boundaries = [...cuts].sort((a, b) => a - b)
    return boundaries.slice(0, -1).map((start, index): SelectedInterval => {
      const end = boundaries[index + 1]
      const explanations = day.explanations.filter(value => Date.parse(value.started_at) < end && Date.parse(value.ended_at) > start)
      const pending = day.pending_explanations.find(value => Date.parse(value.started_at) < end && Date.parse(value.ended_at) > start)
      const base: SelectedInterval = { ...item, started_at: new Date(start).toISOString(), ended_at: new Date(end).toISOString(), kind: 'work' }
      if (explanations.length) {
        const reasons = [...new Set(explanations.map(value => categories.find(category => category.code === value.category_code)?.label ?? value.category_code))]
        return { ...base, annotation: { state: 'explained', label: `Объяснение: ${reasons.join(', ')}`, source: 'Объяснение сотрудника' } }
      }
      return pending ? { ...base, request_id: pending.id, request: pending, annotation: { state: 'pending', label: 'Требует объяснения', source: 'Серверный запрос объяснения' } } : base
    })
  })
  return [...work,
    ...day.activity_intervals.map((item: ActivityInterval) => ({ ...item, kind: 'activity' as const, status: item.state, source: 'Endpoint Agent' }))]
}
export function intervalLabel(item: SelectedInterval, timezone: string) {
  return `${item.kind === 'work' ? 'Рабочий статус' : 'Компьютер'} · ${item.status} · ${statusLabels[item.status] ?? item.status} · ${timeText(item.started_at, timezone)}–${timeText(item.ended_at, timezone)}${item.annotation ? ` · ${item.annotation.label}` : ''}`
}

export function WorkTimeRing({ day, onSelect, mini = false, zoom = false, categories = [] }: { day: WorkDay; onSelect?: (item: SelectedInterval) => void; mini?: boolean; zoom?: boolean; categories?: Category[] }) {
  const start = dayStart(day.day)
  const scheduleStarts = day.schedule.map(item => Date.parse(item.started_at)).filter(Number.isFinite)
  const scheduleEnds = day.schedule.map(item => Date.parse(item.ended_at)).filter(Number.isFinite)
  const from = zoom && scheduleStarts.length ? Math.max(start, Math.min(...scheduleStarts)) : start
  const until = zoom && scheduleEnds.length ? Math.min(start + 86400000, Math.max(...scheduleEnds)) : start + 86400000
  const span = Math.max(until - from, 1)
  const totalEvidence = day.coverage.measured_seconds + day.coverage.unknown_seconds
  const coverage = totalEvidence > 0 ? `${Math.round(day.coverage.measured_seconds / totalEvidence * 100)}%` : 'нет данных'
  const intervals = selectableIntervals(day, categories)
  return <svg className={mini ? 'wt-ring wt-ring-mini' : 'wt-ring'} viewBox="0 0 360 360" role={mini ? 'img' : 'group'} aria-label={`Рабочие статусы и компьютерная активность за ${day.day}${zoom ? ', масштаб графика' : ', 24 часа, 00:00 сверху'}`}>
    <circle cx="180" cy="180" r="143" fill="none" stroke="#edf1f5" strokeWidth="22" />
    <circle cx="180" cy="180" r="112" fill="none" stroke="#edf1f5" strokeWidth="18" />
    {intervals.map((item, index) => {
      const a = Math.max(from, Date.parse(item.started_at)), b = Math.min(until, Date.parse(item.ended_at))
      if (!Number.isFinite(a) || !Number.isFinite(b) || b <= a) return null
      const radius = item.kind === 'work' ? 143 : 112, circumference = 2 * Math.PI * radius
      const length = (b - a) / span * circumference, offset = -(a - from) / span * circumference
      return <Fragment key={`${item.kind}-${index}`}><circle cx="180" cy="180" r={radius} fill="none" stroke={statusColors[item.status] ?? '#acb6c3'} strokeWidth={item.kind === 'work' ? 22 : 18}
        strokeDasharray={`${length} ${circumference - length}`} strokeDashoffset={offset} transform="rotate(-90 180 180)"
        className={onSelect ? 'wt-arc' : undefined} role={onSelect ? 'button' : undefined} tabIndex={onSelect ? 0 : undefined}
        aria-label={onSelect ? intervalLabel(item, day.timezone) : undefined} onClick={onSelect ? () => onSelect(item) : undefined}
        onKeyDown={onSelect ? event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(item) } } : undefined}>
        <title>{intervalLabel(item, day.timezone)}</title>
      </circle>{item.annotation && <circle cx="180" cy="180" r={radius} fill="none" stroke={item.annotation.state === 'explained' ? '#8b62ac' : '#d17926'} strokeWidth="8" strokeDasharray={`${length} ${circumference - length}`} strokeDashoffset={offset} transform="rotate(-90 180 180)" pointerEvents="none" aria-hidden="true" />}</Fragment>
    })}
    {!mini && <>
      <text x="180" y="17" textAnchor="middle" className="wt-clock-label">{zoom ? timeText(new Date(from).toISOString(), day.timezone) : '00:00'}</text>
      {!zoom && <><text x="344" y="184" textAnchor="middle" className="wt-clock-label">06</text><text x="180" y="350" textAnchor="middle" className="wt-clock-label">12:00</text><text x="16" y="184" textAnchor="middle" className="wt-clock-label">18</text></>}
      <text x="180" y="162" textAnchor="middle" className="wt-total">{durationText(day.totals.work_seconds)}</text>
      <text x="180" y="187" textAnchor="middle" className="wt-center-label">подтверждено за день</text>
      <text x="180" y="215" textAnchor="middle" className="wt-center-label">Данные ПК: {coverage}</text>
    </>}
  </svg>
}
