# Endpoint Operation v1 Design

## Scope

Implement one versioned, service-to-service Endpoint Operation:
`context.diagnostic.collect`. Endpoint Platform remains the sole agent control
plane; Helpdesk becomes a caller of a safe HTTP API and does not connect to an
agent. Existing Device Context, enrollment, updates, Gateway WSS and
transitional HTTP pull remain compatible.

## Contract

`EndpointOperationCreateV1` is strict (`extra="forbid"`) and contains a
literal capability, `DiagnosticCollectionParametersV1(reason)`, and optional
opaque `EndpointOperationCorrelationV1`. Correlation has only normalized
source system/entity identifiers and optional UUID request id. The reason is
1–256 characters, control-character- and URL-free. Route device identity and
`requested_by_service` are never accepted in the body.

The public projection contains only stable operation identity, capability,
mapped public lifecycle, timestamps, correlation, result availability and
warnings. A completed diagnostic result exposes profile, collected time,
reason, warnings, bounded process `name`/`state`, and one centrally redacted
excerpt up to 8192 characters. No raw Command/CommandResult/credential,
session/sequence, exception, path or raw result crosses this boundary.

## Persistence and API

Add `EndpointOperation` with bounded JSON parameter/correlation columns,
unique `(requested_by_service_client_id, idempotency_key)`, constrained public
status/capability and nullable private collection/command relations. A second
relation constrains operation ↔ transport command. The new Alembic revision
follows `0013_runtime_session_heartbeat`.

`POST /api/v1/devices/{device_id}/operations` requires `operations.create` and
an 8–128 printable, trimmed `Idempotency-Key`. The first matching request is
201; byte-equivalent normalized replay is 200; a mismatched payload is 409
with a stable code. `GET /api/v1/operations/{operation_id}` requires
`operations.read` and restricts access to the same ServiceClient—not a
specific credential—so rotation preserves access. Capabilities use
`devices.read`. A default-false `ENDPOINT_OPERATIONS_API_ENABLED` switch keeps
all operation routes non-operational until enabled.

Creation atomically persists operation, private diagnostic ContextCollection
and a redacted audit event. Reads/replays and terminal state changes append the
specified `endpoint.operation_*` audit actions without raw parameters/results.

## WSS and agent

Operation collections are marked WSS-only and are excluded from the legacy
HTTP-pull selector. `CommandService` is the only delivery source. It selects
operation work deterministically, commits command and delivery before sending,
and rebuilds a `GatewayCommandV1` with only typed diagnostic parameters and
server-owned identifiers. Existing collections retain their present behavior.

ACK/result handlers atomically synchronize private command/collection and the
linked operation. A terminal result must match device/session/command/relation
and have an idempotent digest; the diagnostic envelope is validated, redacted
and snapshot-persisted before the WSS result ACK. Offline work remains queued
and a server deadline transitions it to expired.

The existing neutral `CommandExecutor` remains the runtime; the capability
already uses a fixed `SystemProbe` path and strict Gateway parameter allowlist.
No GUI, Helpdesk client, old orchestrator or generic executor is imported.

## Verification

TDD covers contracts/schemas/fixtures, authorization/idempotency, persisted
operation lifecycle, WSS-only selection/delivery/reconnect/result safety,
agent typed execution and release dependency scanning. Focused suites are the
contract, operation, gateway, context, architecture, packaging and agent
runtime/transport suites, followed by compileall and full pytest.

## Self-review

No production operation is required. The design has one service capability,
one private transport relation, no helpdesk-specific WSS field and no generic
execution path. Its only external dependency is the existing Pydantic v2,
FastAPI and SQLAlchemy 2 patterns already pinned by the repository.
