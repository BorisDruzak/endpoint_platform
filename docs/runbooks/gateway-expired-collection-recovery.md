# Gateway disconnect caused by expired collection delivery

The 2026-09-29 ADMIN-2 incident was reproduced against the deployed command builder
without committing the probe transaction. Ordinary `connect-refresh` baseline and
inventory requests had expired while the agent was offline. Delivery created a
new command using the old deadline, so `GatewayCommandV1` rejected its timing with
`deadline_at must be after created_at`. The Gateway closed the session with
`internal_error`; reconnect repeated approximately every five seconds.

`context.repository.expire_overdue_collections` now expires ordinary pending or
in-flight collections before connect refresh and command selection. Active linked
commands/deliveries become expired in the same transaction. Collections owned by
Endpoint Operations use their existing deadline/audit state machine. Received,
validated and terminal results, absent deadlines and other devices are preserved.

Connect refresh keys use the 15-minute delivery window rather than the observation
freshness period. Snapshot freshness and active-request deduplication still apply;
a same-day reconnect can request fresh work after the previous request expires.

Apply the verified immutable server release through
`deploy/server/PRODUCTION_RUNBOOK.md`, keeping its predecessor for rollback. No
migration, manual SQL repair, credential reset or TLS bypass is needed. Verify a
fresh open session with advancing heartbeats, no new `internal_error` closes, and
successful baseline/inventory collection. The Windows package stays unchanged.
