# Update Rollout and Rollback Control Plane Design

## Goal

Deliver the server-side control plane for immutable agent builds, targeted
rollouts, outcome reporting, and controlled rollback.  It enables the already
imported `pc_agent` self-update protocol without changing the agent runtime,
launcher, release builders, WebSocket transport, UI, artifact upload, or a
remote host.

## Existing compatibility boundary

`pc_agent` already treats the assigned server rollout as authoritative.  It
downloads one immutable archive, verifies its SHA-256 and size, writes
`pending_update.json`, exits with code 42, and lets the launcher verify,
publish, or roll back the version.  A launcher-reported failure is terminal
for that request; `scheduled` is not success.  A successful post-restart
handshake is the only success signal.

The Endpoint Platform server currently owns skeletal `update_builds`,
`update_rollouts`, `update_targets`, and `update_reports` tables.  This work
turns those ownership records into an auditable control plane.  It does not
claim wire compatibility with the legacy Helpdesk `/api/devices/*` endpoints:
Endpoint Platform publishes a new strict `/agent/v1/updates/*` contract for a
future agent transport adapter.

## Scope and non-goals

In scope:

- immutable build registration by authenticated administrators;
- build metadata validation for a pre-existing HTTPS artifact URL;
- canary and bulk rollout lifecycle, explicit target assignment, pause and
  completion;
- controlled rollback as a new rollout to an older immutable build;
- device-authenticated recommendation, acknowledgement and outcome-report
  endpoints;
- idempotent outcome reports, atomic audit events and redacted diagnostics;
- strict contracts, OpenAPI and PostgreSQL concurrency/migration tests.

Out of scope:

- binary upload or blob storage;
- a Windows/Linux release build, version bump, launcher or `pc_agent` change;
- WebSocket command delivery, automatic agent download, UI pages, Helpdesk
  integration, Nginx/DNS/TLS changes, or deployment;
- bulk execution against a real device.

## Build records

An administrator creates a build with these validated immutable fields:

- `build_identifier`, semantic version, platform (`windows_amd64` or
  `linux_amd64`), channel (`stable` or `canary`);
- HTTPS `artifact_url`, artifact filename, archive type (`zip` or `tar.gz`),
  positive size and lowercase 64-character SHA-256;
- optional bounded public release notes.

The unique identity is `(platform, channel, version)`.  A second request with
the exact same immutable manifest is idempotent; a conflicting manifest is
rejected.  A build is never edited or deleted while it is referenced.  The
server neither downloads nor serves the artifact in this increment, so the
artifact URL may point only to the separately managed HTTPS release store.

## Rollouts and rollback

A rollout selects one registered build and has a unique identifier, a mode
(`canary`, `bulk`, or `rollback`), a lifecycle (`draft`, `active`, `paused`,
`completed`, `cancelled`) and an optional bounded reason.  Targets are an
explicit deduplicated device set.  Target assignment is legal only while the
rollout is `active`; a device may have at most one active target at a time.

Canary and bulk are separate rollout records.  Bulk is created only from a
completed canary for the same build, with an explicit administrator action.
The server records but does not infer the canary success threshold in this
increment.  Completion is an explicit state transition permitted only after
every target has a terminal outcome.

Rollback never rewrites a build or a prior rollout.  It is a new active
`rollback` rollout that targets the affected devices with a previously
registered compatible build; its reason must name the triggering rollout.
This matches the existing launcher model, which accepts a server-recommended
older release as an ordinary verified update.

## Agent transport contract

Device authentication uses the existing Endpoint Platform bearer credential;
the device identifier is resolved server-side, never trusted from request
body.  The strict V1 routes are:

- `GET /agent/v1/updates/recommendation` returns no assignment, or the one
  active target's immutable manifest and opaque `operation_id`;
- `POST /agent/v1/updates/{operation_id}/ack` records `requested` or
  `scheduled` idempotently;
- `POST /agent/v1/updates/{operation_id}/reports` records a bounded terminal
  launcher/handshake outcome (`applied`, `failed`, `rolled_back`).

The recommendation exposes only metadata required for the existing
`pending_update.json` flow: platform, channel, version, artifact URL,
filename, archive type, SHA-256, size, operation id and reason.  Reports
contain the observed version, status, bounded safe code/message and a
client-generated idempotency key.  They never contain raw bearer tokens,
pending-update payloads, archive paths, stack traces or logs.

The target progresses monotonically:
`assigned → requested → scheduled → applied`, or a terminal `failed` /
`rolled_back`.  Repeating the same idempotency key and payload returns the
prior state; reusing a key with a different payload fails closed.  No report
can move an inactive, foreign-platform or foreign-device target.

`applied` represents the future adapter's observed post-restart handshake;
it is not emitted by the server merely because the agent scheduled a restart.

## Authorization, audit and concurrency

All admin mutations require the existing interactive administrator session
with an explicit `updates:write` scope.  Agent endpoints authenticate only the
device credential and cannot create builds, rollouts or targets.

Build creation, rollout lifecycle transitions, target assignment, ack and
report mutation each append one immutable audit event in the same transaction.
Audit details retain public identifiers, statuses and redacted bounded reasons
only.  Existing recursive redaction applies before persistence, including to
client correlation headers.

Target transitions lock the target row with `FOR UPDATE`; active assignment
uses a PostgreSQL partial uniqueness constraint / transaction check so two
concurrent admin requests cannot give a device two active rollouts.  Rollout
completion locks its target set and re-evaluates terminal states.  Agent report
idempotency is unique per target and report key.

## Migration and downgrade

One forward Alembic revision expands the existing ownership tables with the
validated build manifest, rollout mode/reason/lifecycle timestamps, target
operation and lifecycle fields, and report idempotency/safe detail fields.
It adds supporting indexes and constraints.

Downgrade is fail-closed: before dropping state it disables every active
rollout and marks active targets cancelled, so a rollback cannot re-enable an
assignment whose state no longer exists.  Existing build identities and
historic reports remain preserved where the prior schema can represent them.

## Verification

Tests cover manifest immutability, malformed URL/digest/version rejection,
canary-to-bulk precondition, rollback compatibility, target ownership races,
device isolation, report idempotency/state monotonicity, audit rollback and
redaction.  PostgreSQL tests cover concurrent assignment/reporting and a
populated upgrade/downgrade path.  Acceptance runs generated contracts/OpenAPI,
full standalone tests, a disposable PostgreSQL database, Alembic SQL, Ruff,
compile, extraction and a no-`pc_agent` diff check.
