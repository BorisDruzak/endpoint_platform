# Work Activity Analytics v1

The administrative Console route is `/admin/activity-analytics`. It uses the
existing Windows User Sensor → Agent → Gateway WSS → applied-policy validation
→ Activity ingestion path. No new collector, agent release, policy activation,
document content or browser URLs are required.

## Storage and migration

Run `python -m alembic upgrade head` as part of the normal server release, before
starting the new API/Gateway and worker. Revision `0038_activity_analytics` adds:

- `activity_intervals`: compact half-open measured intervals, indexed by account,
  device and time, with state, foreground process/category and policy version.
- `activity_cursors`: one durable device watermark and latest observed account.
- `activity_daily`: one aggregate per account, report timezone and calendar day.

The migration does not change Context, SecurityEvent or policy retention. It
does not reconstruct time from old ContextSnapshot records: unchanged historical
heartbeats cannot be recovered. Analytics history starts with newly received
observations after this release. Downgrade removes these three analytics tables
and their history; it does not alter existing application data.

## Measurement rules

- An isolated observation has zero measured duration. Another accepted sample
  brackets the preceding state. The previous state owns `[previous, next)`.
- Unchanged samples extend one interval. State, account, application or policy
  changes start another interval. Intervals split at supported calendar borders.
- A gap above 45 seconds is wholly UNKNOWN; no optimistic ACTIVE or IDLE tail is
  added. Reports never extend the last observed state to the present.
- Replays and out-of-order timestamps cannot add time. Context and analytics
  persist in the same transaction, after existing validation/policy checks.
- Accounts are case-normalized with their OS-provided domain intact. Bare logins
  are device-scoped. AD aliases, UPN/SAM equivalence and renamed accounts are not
  resolved. No display-name matching is used.
- After a gap followed by a different account, the gap has no employee
  attribution. Gaps exceeding 24 hours also have no defensible employee owner;
  their device-only detail is bounded by detail retention.
- Overlapping account/device intervals are unioned by a sweep. Reporting state
  precedence is ACTIVE, IDLE, LOCKED, DISCONNECTED, UNKNOWN. Stable device order
  allocates the application in overlaps. `overlap_seconds` discloses this
  ambiguity; it is not proof of simultaneous human work. Summed app time never
  exceeds the user's deduplicated ACTIVE duration.
- Applications count only confirmed foreground while ACTIVE. Missing process
  data becomes “Приложение неизвестно”. Browser extension context is optional.
- Coverage is confirmed time divided by the observation horizon **within each
  day**, including interior UNKNOWN gaps. Period reports sum these daily
  horizons. Unobserved days/outside-horizon time are not assumed working hours.
  A short, complete observation window does not imply a complete workday.
- Timeline UNKNOWN outside the horizon is explicitly unattributed. Current
  state freshness uses sensor `observed_at`, independently of device transport
  presence. ACTIVE is input/session activity, not a productivity measurement.

## Configuration and worker

| Environment variable | Default | Bounds |
| --- | --- | --- |
| `ACTIVITY_ANALYTICS_DETAIL_DAYS` | `14` | 1–90 |
| `ACTIVITY_ANALYTICS_AGGREGATE_DAYS` | `90` | detail retention through 365 |
| `ACTIVITY_ANALYTICS_MAX_GAP_SECONDS` | `45` | 15–60 |
| `ACTIVITY_ANALYTICS_TIMEZONE` | `Asia/Yekaterinburg` | valid IANA zone |

Use the same configuration for API and worker. `tzdata` supplies IANA calendars
on Windows; Linux can use system tzdata. The organization timezone and UTC are
the supported report calendars. Arbitrary browser timezones are not silently
used. Changing the organization timezone does not retroactively rebuild expired
detail into a new calendar; keep this setting stable for historical reports.

Ingestion marks affected user-days dirty with an atomic upsert. The existing
worker rebuilds at most 16 days per transaction and 256 per cycle, skipping locked
rollups. It stops early when the queue drains. This covers 120 accounts in two
calendars per normal minute. Rollup row locks and dirty marks prevent a concurrent
ingestion from being lost. Reports disclose pending aggregates and their last
completed timestamp rather than silently treating them as live totals.

Cleanup deletes at most 500 intervals and 500 daily aggregates per normal minute.
Whole calendar days are preserved; detail may survive up to an additional day
across calendar boundaries. Dirty users' detail is not removed before rollup
completion. Stale cursors expire with aggregate retention. Worker downtime can
extend physical retention until its bounded backlog drains.

## API and limits

All endpoints require the existing administrator session and return `no-store`:

- `GET /api/admin/console/activity-analytics/overview`: `period` (`today`,
  `yesterday`, `7d`, `30d`, `custom`), `since`/`until` inclusive local dates,
  `timezone`, `search`, `sort` (`active`, `last_observed`, `state`, `user`),
  `limit` 1–100 and `offset` 0–100000. Queries are batched, without a per-device
  query or raw-observation scan.
- `GET .../user`: the same report period plus canonical `user_key`; totals,
  daily statistics and application/category distribution.
- `GET .../timeline`: canonical `user_key`, `day`, `timezone`; a single day's
  server-resolved segments, including separate Gateway connection gaps.

Detail and timeline reads append `activity.analytics.read` to the existing audit.
The audit object ID is a SHA-256 account reference, fitting the existing bounded
audit schema. Gateway transport gaps are device facts, never employee states.

Oversized reports fail explicitly rather than silently truncating: 5000 devices,
100000 daily rows, 20000 source intervals per user/day and 2000 Gateway sessions
per timeline. An oversized rollup remains pending and retains its source. A
timeline outside detail retention returns 410 while daily totals remain usable.

Unsupported agents, missing OS identity and sensors with no accepted observations
show UNKNOWN with unavailable measurements, not zero working time. Enabling a
sensor or changing production policy remains an operator action.

Policy changes can race with already queued Activity frames. The Gateway drops
samples that do not satisfy the current applied policy without closing WSS, so
the same connection can deliver and acknowledge the new version. Disabled or
unacknowledged collection never writes Context or analytics. Malformed frames,
invalid observation timestamps and protocol/authentication failures retain their
existing rejection behavior.
