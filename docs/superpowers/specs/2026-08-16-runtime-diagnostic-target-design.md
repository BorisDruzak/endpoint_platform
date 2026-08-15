# Runtime Diagnostic Target API Design

## Goal

Give Helpdesk a verifiable, server-to-server read of the runtime state for an
already selected Endpoint device. Endpoint owns runtime presence; it does not
resolve Registry people, bindings, assets, registration, or login eligibility.

## Authority and access boundary

`device_ref` is exactly the existing Endpoint `Device.id` UUID. It is opaque
to Helpdesk and is used only as an exact primary-key lookup. The Runtime API
does not accept, inspect, or derive a person, binding, asset, MAC address, IP
address, installation identifier, token, or arbitrary agent metadata.

The read route accepts a service bearer over the existing HTTPS boundary. It
requires both of the following, without an alternative authorization path:

- `ServiceClient.client_identifier == "helpdesk"`;
- credential scope `helpdesk.diagnostic_target.read`.

This prevents another service principal from reusing the scope and prevents a
Helpdesk credential without that exact scope from reading runtime state.

## Durable runtime model

The device calls `POST /agent/v1/runtime/heartbeat` with its current Endpoint
device bearer and the existing strict `agent_heartbeat_v1` body. The server
verifies that the body `device_id` is the device identified by the bearer. It
upserts the device instance's agent version and server-observed last-seen time,
then records/extends a durable gateway session. Client `reported_at` remains
diagnostic payload data and never establishes presence.

Runtime projection uses the most recent durable session. A session is online
only while its server-issued expiry is later than the current server time. The
fixed TTL is 90 seconds. `last_handshake_at` is the server-observed heartbeat
time, and `last_seen_at` is the latest durable runtime observation. Both are
null when no accepted heartbeat has ever been recorded. `connection_state` is
strictly `online` or `offline`, with `online` matching it exactly.

## Service API

`GET /service/v1/runtime/devices/{device_ref}` requires a non-empty,
bounded, printable-ASCII `X-Correlation-ID`. The response writes exactly the
same value to both `X-Correlation-ID` and the response envelope:

```json
{
  "schema_version": "endpoint_runtime_v1",
  "correlation_id": "…",
  "data": {
    "device_ref": "…",
    "online": true,
    "connection_state": "online",
    "last_seen_at": "2026-08-15T00:00:00Z",
    "last_handshake_at": "2026-08-15T00:00:00Z",
    "agent_version": "3.2.11"
  }
}
```

A missing Endpoint device is the only 404 outcome and returns exactly:

```json
{
  "correlation_id": "…",
  "data": {
    "status": "not_found",
    "code": "endpoint_device_not_found"
  }
}
```

Malformed UUIDs, missing or malformed correlation identifiers, malformed
heartbeats, correlation mismatches, authorization failures, and internal
unavailability do not use the 404 envelope. API outputs use explicit Pydantic
models with `extra="forbid"` to make the field allowlist executable.

## Audit and Helpdesk adapter boundary

The Endpoint audit event records only service attribution, an opaque device UUID
and the existing hashed request ID. It carries no credentials, networking
identifiers, installation identifiers, or raw heartbeat fields.

Helpdesk server code is outside this repository and remains unchanged. This
repository instead includes adapter-facing fixtures/parser tests which require
the strict response schemas, compare only redacted shadow projections, and
classify malformed, mismatched-correlation, and unavailable responses as
fail-closed diagnostic-target failures.

## Verification

Tests cover device bearer correlation, TTL expiry and absence, active
heartbeat, double authorization requirement, exact correlation propagation,
strict success and 404 envelopes, excluded secrets/network identifiers in API
and audit, and adapter fixture fail-closed behavior. Contract artifacts are
regenerated after model changes.

## Out of scope

This task removes only the local runtime-presence dependency. A separate
Endpoint/Registry Authority task must own any removal of `registry_*` or
`device_registration_*`, including external registration commands, bindings,
account sessions, pairing, login eligibility, idempotency, and rollback
reconciliation.
