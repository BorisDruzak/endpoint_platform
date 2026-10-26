export type PowerEvent = {
  schema_version: 'power_event_v1'; event_identifier: string
  event_kind: 'OS_STARTED' | 'OS_SHUTDOWN_STARTED' | 'OS_SLEEP_STARTED' | 'OS_RESUMED' | 'OS_UNEXPECTED_SHUTDOWN_REPORTED'
  occurred_at: string; observed_at: string; boot_id: string; source: string; native_record_id: string
  evidence: 'transition' | 'request' | 'reported'; sleep_subtype: 'sleep' | 'hibernate' | 'hybrid' | 'unknown' | null
}
export type PowerSummary = {
  status: 'online' | 'unknown' | 'sleep' | 'shutdown'; online: boolean; last_seen_at: string | null
  source_status: { schema_version: 'power_source_status_v1'; source: string
    availability: 'READY' | 'DEGRADED' | 'UNAVAILABLE' | 'UNSUPPORTED'; reported_at: string
    coverage_started_at: string | null; loss_count: number; reset_count: number } | null
  source_fresh: boolean; history_available_from: string; latest_event: PowerEvent | null
}
export type PowerPage = { summary: PowerSummary; data: PowerEvent[]; total: number; limit: number; offset: number; has_more: boolean }
