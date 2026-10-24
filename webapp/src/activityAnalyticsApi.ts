import type { PowerEvent } from './powerApi'
export type ActivityState = 'ACTIVE' | 'IDLE' | 'LOCKED' | 'DISCONNECTED' | 'UNKNOWN'
export type AnalyticsMetrics = {
  seconds: Record<ActivityState, number>; observed_span_seconds: number; coverage: number | null
  applications: { label: string; category: string; seconds: number }[]; categories: Record<string, number>
  overlap_seconds: number; pending: boolean; updated_at: string | null
}
export type AnalyticsDevice = { id: string; name: string; online: boolean }
export type Employee = {
  user_key: string | null; user_login: string | null; devices: AnalyticsDevice[]; state: ActivityState
  fresh: boolean; last_observed_at: string | null; metrics: AnalyticsMetrics | null; reason: string | null
}
export type AnalyticsMeta = {
  today: string
  since: string; until: string; timezone: string; timezones: string[]; detail_available_from: string
  aggregate_available_from: string; max_gap_seconds: number; generated_at: string; collection_enabled: boolean
}
export type AnalyticsOverview = {
  data: Employee[]; total: number; offset: number; limit: number; summary: Record<string, number>; meta: AnalyticsMeta
}
export type AnalyticsUser = {
  data: Employee; daily: { day: string; metrics: AnalyticsMetrics | null; timeline_available: boolean }[]; meta: AnalyticsMeta
}
export type TimelineSegment = {
  started_at: string; ended_at: string; seconds: number; state: ActivityState; process_name: string | null
  application_category: string | null; device_id: string | null; overlap: boolean; attributed: boolean
}
export type AnalyticsTimeline = {
  power_events?: { device_id: string; event: PowerEvent }[]; power_events_truncated?: boolean
  day: string; timezone: string; started_at: string; ended_at: string; data: TimelineSegment[]
  connection_gaps: { device_id: string; started_at: string; ended_at: string }[]; devices: AnalyticsDevice[]
}

export const stateLabels: Record<ActivityState, string> = {
  ACTIVE: 'Активен', IDLE: 'Бездействие', LOCKED: 'Сеанс заблокирован', DISCONNECTED: 'Сеанс отключён', UNKNOWN: 'Нет достоверных данных',
}
export const categoryLabels: Record<string, string> = {
  office: 'Офисные', browser: 'Браузеры', business_app: 'Рабочие приложения', system: 'Системные', remote_access: 'Удалённый доступ', other: 'Прочие',
}
export function duration(seconds: number | null | undefined) {
  if (seconds == null) return '—'
  const whole = Math.floor(seconds)
  if (whole < 60) return `${whole} с`
  if (whole < 3600) return `${Math.floor(whole / 60)} мин ${whole % 60} с`
  return `${Math.floor(whole / 3600)} ч ${Math.floor(whole % 3600 / 60)} мин`
}
