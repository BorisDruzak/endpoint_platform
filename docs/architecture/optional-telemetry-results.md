# Optional telemetry results

The Gateway processes each negotiated Activity, Browser Status or Sensor Health
report in a dedicated database session. A domain rejection rolls back that
report and leaves heartbeat, policy and command processing available on the same
connection. Security batches from legacy agents remain atomic; a rejected batch
receives no new frame. Disabled features, malformed or oversized frames, invalid
direction, authentication and command-state violations retain their fatal path.
Unexpected database failures also retain the existing failure path.

Updated agents advertise `endpoint.telemetry-results.v1` in AgentHello. An updated
Gateway acknowledges it in `GatewayHelloV1.protocol_features`. The default empty
list is omitted from the wire, including nested envelope serialization, because
legacy agents reject extra fields. Upgrade the provider before agents: old
providers reject unknown AgentHello features. There is no implicit protocol or
authentication downgrade.

`TelemetryResultV1` (`telemetry_result_v1`) is carried by `telemetry_result`.
It identifies the original `report_kind`, `report_id` UUID and
`report_sequence`. `disposition` is `accepted`, `retry_later` or `rejected`;
`reason_code` is a maximum 64-character lowercase code with underscores and
digits. The current provider emits `persisted` / `domain_rejected`; it never
copies exception text or report contents into a result. For transient control or
database failures it sends no success disposition. Non-durable samples are
replaced by later observations; their results never terminate the agent.

Security results additionally require unique `event_identifiers` (1–50), in
original batch order. Each sibling runs inside a savepoint, and the outer
transaction commits before **any** accepted/rejected subset is sent. All valid
siblings persist once; permanent poison events receive rejection. Lost responses
can replay the same batch safely. SQLite explicitly begins its outer transaction
before savepoints to avoid legacy sqlite3 RELEASE committing a sibling early.
Legacy `security_event_ack` still acknowledges only the exact complete batch
after commit. Updated peers use subset results instead of weakening that ACK.

The security sender registers each transmitted sequence while holding the same
lock used by disposition handling. It accepts only a matching pending batch ID,
a recently transmitted sequence (bounded to 128), and an exact still-pending
subset in original order. A retry-later disposition keeps rows queued. Accepted
or rejected rows are deleted atomically from the protected spool; permanent
rejections increment durable `SecurityEventSpoolStats.rejected_permanent`.
Duplicate, conflicting, stale or foreign dispositions cannot delete other rows
or increment counters twice. The existing 24-hour DLP acceptance and spool bounds
are unchanged.

Sensor-health collection/projection retries expected local `OSError` /
`ValueError` failures. Browser collection additionally handles missing projected
family keys. Spool handling isolates expected local filesystem/SQLite/spool
errors. Transport sends are outside those collector boundaries, cancellation
propagates, and concurrent control transport errors retain priority when the
runtime selects a completed task. Heartbeat remains 30 seconds and presence
expiry remains 90 seconds.
