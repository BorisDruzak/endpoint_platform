# Gateway Contracts V1 Design

## Purpose

Deliver the first standalone artefact of Wave 0 / 6A: a versioned, strict
contract package shared by the future Agent Gateway, the existing `pc_agent`,
and service clients. This increment deliberately contains no server, database,
network connection, enrolment persistence, production configuration, or agent
runtime integration.

## Scope and boundaries

The package defines these immutable V1 payloads:

- `DeviceIdentityV1`
- `AgentSessionV1`
- `EnrollmentRequestV1`
- `EnrollmentResponseV1`
- `AgentCommandV1`
- `AgentCommandAckV1`
- `AgentResultV1`
- `AgentHeartbeatV1`
- `AgentBuildRecommendationV1`

Each payload carries a literal `schema_version`. Models reject unknown fields,
use UUIDs for durable identifiers, require timezone-aware timestamps, and put
bounded limits on strings, JSON values, and lists. Commands identify an
allowlisted capability and JSON-compatible parameters only. The contract
contains no field that accepts executable shell, Python, PowerShell, RouterOS,
or Scheme content.

Device tokens, enrolment campaign tokens, admin secrets, certificate material,
and passwords are never represented in fixtures or schemas. The one-time raw
device token returned during enrolment belongs to the future server/agent
transport boundary, not to this package's persisted samples.

## Architecture

`endpoint_contracts` is a Python-only package based on Pydantic v2. It has no
FastAPI, SQLAlchemy, filesystem, or network dependency. Pydantic models are
the single source of truth. JSON Schema files and an OpenAPI 3.1 document are
derived from those models and committed as reviewable API artefacts.

The package is divided by transport concern:

- `identity.py` defines device and session identity.
- `enrollment.py` defines the request and non-secret response envelope.
- `commands.py` defines command, acknowledgement, result, correlation, and
  lifecycle-status types.
- `telemetry.py` defines heartbeat and build-recommendation messages.
- `json_types.py` constrains JSON-compatible parameter/result values.

The first Gateway server will import these contracts but will own persistence,
authorization, token generation and storage. The existing agent will consume
the models only after its Gateway transport task; its current launcher and
orchestrator are not modified in this increment.

## Payload rules

`AgentCommandV1` has a server-created `command_id`, target `device_id`, a
bounded capability name, bounded JSON parameters, service attribution, an
idempotency key, creation/deadline timestamps, and optional opaque
correlation. The command does not use Helpdesk ticket IDs as identity.

`AgentCommandAckV1` and `AgentResultV1` repeat command and device identity so
the future Gateway can reject cross-device or conflicting replay. Result and
acknowledgement statuses use closed literal sets. Timestamps are UTC-aware
values; a deadline must be after creation.

`EnrollmentRequestV1` includes a platform and non-secret installation or
hardware identity needed by the future campaign/claim flow. The response
contains the new `device_id`, assigned policy identifier, and a response
receipt suitable for retry-safe delivery. It deliberately does not prescribe
database columns or token hashing.

`AgentHeartbeatV1` communicates only bounded runtime metadata required for a
future connection health view. `AgentBuildRecommendationV1` is metadata only:
immutable version, platform, artifact location, size, SHA-256 and minimum
launcher version. It neither downloads nor applies an update.

## Generated artefacts and compatibility

For every public V1 model, a deterministic JSON Schema is committed under
`contracts/jsonschema/`. `contracts/openapi/endpoint-platform-v1.yaml`
declares the future agent HTTP/WSS message shapes by reference to the same
schemas. Tests regenerate and compare these artefacts, making any incompatible
contract edit visible in review.

Synthetic golden fixtures under `tests/fixtures/contracts/` are valid examples
for each public message. Tests validate them both through Pydantic and their
committed schemas. Fixtures use fixed UUIDs and UTC timestamps only; they have
no host paths, real device data, credentials, or token-like values.

Generated JSON Schema and OpenAPI components enforce every applicable
single-field and structural rule, including the V1 capability allowlist,
recursive JSON depth/container/string bounds, and relative artifact paths.
Rules JSON Schema cannot express remain model-only: UTC normalization,
cross-field deadline ordering, aggregate JSON node count, and serialized byte
size. Generated `$comment` annotations identify those gaps; tests do not claim
model/schema rejection parity for them.

The initial compatibility policy is additive-only inside V1: a new required
field, changed field type, removed value, or changed schema version requires a
new schema version and a new compatibility decision. Adding optional fields is
also deferred until a consumer needs one, avoiding speculative surface area.

## Validation, error handling, and tests

Models use `extra="forbid"` and are frozen after validation. Tests prove that
unknown fields, naive datetimes, invalid UUIDs, over-limit strings/lists,
invalid idempotency keys, unknown status values, nested non-JSON values, and a
deadline preceding creation are rejected. A representative malicious `shell`
field is rejected rather than retained as command data.

Contract tests run entirely locally:

```text
python -m pytest tests/contracts -q
```

No service is started and no remote host is contacted. Later Gateway,
enrolment, WebSocket, update and rollback tasks add their own integration tests
without changing this package's responsibility.

## Acceptance criteria

- All nine public V1 models strictly validate their documented payloads.
- JSON Schema and OpenAPI are regenerated from the models and match committed
  artefacts.
- Golden fixtures validate and contain no secret, credential, host path or
  production device data.
- Focused contract tests pass, the existing extraction verifier still passes,
  and the repository compiles.
- No file under `pc_agent/` is changed by this increment.
