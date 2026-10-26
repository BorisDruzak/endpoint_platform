# WorkTime v1

WorkTime is an Endpoint module backed by the Endpoint PostgreSQL database. It has
its own personnel records and retention policy. Activity remains technical
evidence. ACTIVE does not create work, IDLE does not establish absence, and
UNKNOWN does not establish either work or absence.

## Enablement and authority

`ENDPOINT_WORKTIME_ENABLED` defaults to false. Enable only after identity, role,
schedule, categories, retention and pilot scope have been approved. OIDC employee
cookies authorize `/api/employee/worktime`; device, service and administrative
cookies do not authorize that interface. The shared employee dependency enforces
CSRF on mutations. Responses use `Cache-Control: no-store`.

Self-write APIs derive the person from the authenticated server session and reject
unknown JSON properties, including injected `person_id`. Read selectors and HR
schedule selectors pass through `authorize_person`, which loads the target's
persisted department. Managers can read/approve within their explicitly granted
department; HR and WorkTime administrators have their explicit department or
organization scope. An Endpoint administrator has no implicit personnel rights.
Approval requires a different person from the correction requester.

## Durable records and serialized events

Migration `0041_worktime`, after `0040_identity_sso`, adds thirteen tables:

- `worktime_state`: one serialization/status row per confirmed person.
- `worktime_events`: append-only start/end/break/off-PC/resume events.
- `worktime_schedules`: immutable effective-dated schedule versions.
- `worktime_categories`: configurable explanation directory.
- `worktime_explanations`: immutable interval explanations.
- `worktime_corrections`: immutable proposed interval/status corrections.
- `worktime_approvals`: one immutable approval or rejection per correction.
- `worktime_explanation_requests`: stable durable measured-return requests.
- `worktime_activity_bindings`: explicit verified temporal account mappings.
- `worktime_audit`: append-only personnel mutation audit references.
- `worktime_retention_policies`: append-only policy decisions.
- `worktime_timesheets`: immutable approved monthly versions and source digest.
- `worktime_timesheet_days`: persisted daily totals and personnel annotations for
  each approved monthly version.

Every person mutation first locks `confirmed_identities` and then
`worktime_state` with PostgreSQL `FOR UPDATE`. The confirmed-identity lock also
serializes the first state-row insertion. All devices therefore operate the same
person state. The caller commits the event, status and audit atomically.

The finite-state machine accepts:

| Current | Action | Next |
| --- | --- | --- |
| ENDED | start | WORKING |
| WORKING | break / off_pc / end | BREAK / OFF_PC / ENDED |
| BREAK | resume / end | WORKING / ENDED |
| OFF_PC | resume / break / end | WORKING / BREAK / ENDED |

An event's instant is the server's UTC time; retrospective edits use correction
requests. Event timestamps must strictly increase. UUID idempotency keys and
request fingerprints distinguish a retry from conflicting key reuse. Reusing a
key returns the original result; incompatible reuse or invalid transitions returns
409. Original events, explanations, proposals and decisions have no edit/delete
API. A subsequent correction produces another proposal and decision.

## Calendar, totals and corrections

Storage uses UTC instants and half-open intervals. Reporting uses
`Asia/Yekaterinburg`, including calendar midnight splitting. Schedules support
weekday lists (Monday=0), overnight shifts and explicit date overrides: `null`
means non-working holiday/weekend; `{start,end}` supplies an exceptional shift.
Both the prior day's effective schedule and today's schedule are evaluated so
changing an assignment does not invent an overnight shift from yesterday.

Live day and month totals are projections of durable events and approved corrections.
Finalizing a closed calendar month persists a separate immutable approved version,
including its daily totals, work intervals, original event references, explanations,
correction proposals/decisions and schedule bounds. Finalized records do not depend
on live technical or personnel source retention. A later approved correction changes
the live projection and requires a new explicit monthly version; it never rewrites
the prior approved version. PostgreSQL triggers reject updates and deletes of both
monthly versions and their daily records. Each approval records an audit reference,
independent finalizer, time, reason and SHA-256 source digest.

Finalization requires HR authority and independent approval authority, a completed
calendar month, no unresolved correction proposals, and unexpired source history.
The same person lock serializes finalization with correction decisions and assigns
unique increasing versions. Retried idempotency keys return the original version.
Employee self-approval is forbidden. HR may propose a correction for another person
only through the explicit HR-scoped endpoint; its actor remains the HR author, who
cannot approve their own proposal. MFA and current target-department authority are
revalidated by the shared authorization boundary.

`work_seconds` includes WORKING and OFF_PC; `off_pc_seconds` is the OFF_PC subset;
`break_seconds` and `scheduled_seconds` are separate. Technical Activity and
explanation category selection never add work seconds. An explanation is a
statement requiring the organization's personnel rules, not an automatic legal,
disciplinary or payroll classification. Corrections overlay the original interval
only after independent approval; a later approved correction takes precedence
on its overlapping portion. No original event is overwritten.

## Technical attribution and measured-return requests

There is no join on OIDC preferred username, email or a similar-looking OS login.
Without an explicit verified `(person, device, user_key, valid_from, valid_until)`
mapping, the employee sees UNKNOWN. Mappings require an authorized WorkTime
administrator and a verification evidence reference. The evidence must be checked
by the operator; the endpoint does not claim to infer AD objectGUID from an OS
login string. Mapping writes lock the device and reject overlapping assignments.
Conflicting mappings or overlapping observations from another OS account suppress
attribution. Employee projections omit OS logins, application/process metadata,
device credentials and verification references.

Attributed observations use the existing Activity `merged_segments` sweep. Two
devices never add the same elapsed second twice. Gaps and unavailable coverage
remain UNKNOWN. A continuous measured IDLE/LOCKED run of at least 1200 seconds,
followed immediately by measured ACTIVE return, may create an explanation request.
The full measured run must fit the assigned schedule. The union of declared
BREAK/OFF_PC intervals and existing explanations is subtracted first; only if the
remaining duration is at least the threshold are its uncovered fragments requested.
Overlapping declarations never double-subtract time. A partial explanation therefore
does not suppress another 29 unexplained minutes from a measured 30-minute run.
Existing overlapping requests suppress duplicate requests after partial answers;
multiple explanations may jointly cover and complete an existing request. No schedule,
UNKNOWN, disconnection, an observation gap or ambiguous identity produces absence
or a request. Calendar-midnight runs are evaluated with the previous day's
timeline. Request IDs deterministically derive from person and exact UTC bounds;
the database additionally enforces uniqueness of those bounds.

`generate_due_requests(session, now=None, batch_size=64)` is the bounded server
maintenance hook. It processes active mapped identities fairly by the persisted
notification-check timestamp; the worker owns commit/rollback. The public pending
read does not mutate state. An employee may request a server-side refresh for a
date; the server reads its own verified data and ignores browser telemetry claims.
Pending requests survive restarts and become completed by matching explanations.
Delivery to Windows/Linux user companions uses the separate Stage E authenticated
transport; these employee APIs contain no device-token delivery mechanism.

## API contract

All paths below are under `/api/employee/worktime`. Dates use ISO calendar strings;
interval inputs require timezone-aware RFC3339 timestamps. Mutation JSON rejects
unknown fields. All event/explanation/correction/schedule commands require
`idempotency_key: UUID`.

| Method / path | Contract |
| --- | --- |
| GET `/categories` | `{categories:[{code,label,requires_comment}]}` |
| GET `/day?day=&person_id=` | Day projection; optional scoped target |
| GET `/month?month=YYYY-MM&person_id=` | `{person_id,month,timezone,days,totals}` |
| GET `/report?month=&person_id=` | Month projection requiring HR authority |
| GET `/people` | Scoped `{people:[{person_id,department_id,status}]}` |
| POST `/transitions` | `{action,idempotency_key}`; stored event with status |
| POST `/explanations` | `{started_at,ended_at,category_code,comment,request_id?,idempotency_key}` |
| POST `/corrections` | `{started_at,ended_at,status,reason,idempotency_key}` |
| POST `/people/{person_id}/corrections` | Explicit HR-scoped correction; same input, authenticated HR author |
| GET `/history?day=&person_id=` | `{events,explanations,corrections,approvals}` |
| GET `/approvals` | Scoped pending corrections, excluding self-approval |
| POST `/corrections/{id}/decision` | `{decision:approved\|rejected,comment,idempotency_key}` |
| GET `/pending` | `{requests:[{id,person_id,started_at,ended_at,source,created_at,state:pending}]}` |
| POST `/pending/refresh?day=` | Server-side generation and pending response |
| GET `/schedules?person_id=` | HR schedule-version history |
| POST `/schedules` | HR `{person_id,effective_from,definition,idempotency_key}` |
| POST `/categories` | Organization WorkTime admin directory configuration |
| POST `/policy` | Organization WorkTime admin retention/threshold decision |
| POST `/activity-bindings` | Scoped WorkTime admin verified temporal mapping |
| GET `/timesheets?month=&person_id=` | Scoped finalized version metadata, newest first |
| POST `/people/{person_id}/timesheets/finalize` | `{month,reason,idempotency_key}`; independent HR approval of closed month |
| GET `/timesheets/{id}` | Immutable finalized version with persisted daily records |
| GET `/timesheets/{id}/export` | HR-scoped CSV of finalized daily/month totals, version, finalizer and digest |

A day contains `person_id`, `day`, `timezone`, current `status`,
`work_intervals:[{id,started_at,ended_at,status,source}]`,
`activity_intervals:[{started_at,ended_at,state,seconds,attributed,overlap?}]`,
`totals:{work_seconds,off_pc_seconds,break_seconds,scheduled_seconds}`,
`coverage:{state,measured_seconds,unknown_seconds}`, `schedule` clipped UTC bounds,
`explanations`, `corrections`, and `pending_explanations`. Full-day technical coverage
includes UNKNOWN outside measured observations, including the future part of today.
An initial unrecorded work interval is ENDED with source `unrecorded`; that source
does not assert that the person was absent.

## Retention and operational limits

Automatic WorkTime deletion defaults disabled. An absent policy or null retention
retains all personnel records. `/policy` records independently approved retention
days, rationale and an inactivity threshold of at least 1200 seconds. A non-null
retention explicitly enables `retain_worktime(session, now=None, batch_size=100)`;
the server worker invokes it in an independent transaction. It locks each person,
expires records in foreign-key-safe bounded batches, retains the event and schedule
predecessors needed at the boundary, and preserves audit/policy decision references.
Recently submitted explanations and recently decided corrections are retained even
when their described interval is older. No Activity table is deleted by this job.
Finalized monthly versions and their daily payloads, including their saved
explanations and approval history, are retained independently and are never purged
by source cleanup. Their retention requires a separately reviewed policy; the
current immutable ledger intentionally has no delete API.

Every deletion persists a monotonic per-person `records_expired_before` boundary.
A day or history intersecting that boundary returns HTTP 410; a month containing
such a day also returns 410. Deleted records can never silently become zero-hour
historical reports. Disabling deletion later does not erase this marker or invent
the missing history. Finalized-version list/read/export remains available after
source expiry, so approved historical totals never disappear into zero reports.
Finalize or export required historical reports before enabling a shorter source
retention window. Activity retention independently deletes its own technical tables
and cannot delete explanations, requests, approvals or personnel events.

The basic API bounds personnel lists to 2000, pending/approval/history schedule
lists to 500, per-binding daily Activity evidence to 20000, and interval mutations
to 31 days. Month APIs return one calendar month. This implementation is a pilot
foundation; role grants, verified account mappings and schedules must be provisioned
for the pilot. Real SSO/AD, installed companion delivery, browser qualification,
production policy decisions and fleet rollout are separate gates.
