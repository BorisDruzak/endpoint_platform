# Endpoint ↔ Helpdesk Service Boundary

## Decision

Endpoint Platform owns device identity, device credentials, Gateway WSS,
technical command delivery, acknowledgements/results, Device Context and
Endpoint Operations.  Helpdesk is a service caller: it owns ticket workflow
and a safe historical operation snapshot, but never a device connection,
agent credential, Gateway session, raw command/result, or agent lifecycle.

The first capability is `context.diagnostic.collect`.  It is read-only and
does not require consent.  This document does not migrate generic tools,
Remote Assist, browser pairing, Helpdesk registration, or any arbitrary-code
execution path.

## Future Helpdesk call

```http
POST /api/v1/devices/{endpoint_device_id}/operations
Authorization: Bearer <Endpoint service credential>
Idempotency-Key: <bounded-key>
Content-Type: application/json

{
  "schema_version": "endpoint_operation_create_v1",
  "capability": "context.diagnostic.collect",
  "parameters": {"reason": "Диагностика по обращению"},
  "correlation": {
    "schema_version": "endpoint_operation_correlation_v1",
    "source_system": "helpdesk",
    "source_entity_type": "ticket",
    "source_entity_id": "<opaque-ticket-id>",
    "request_id": "<uuid>"
  }
}
```

`source_entity_id` is an opaque reference. Endpoint Platform never resolves it
against Helpdesk and has no Ticket model. Correlation is stored only with the
service operation; it is neither an authorization input nor part of the agent
payload. Helpdesk polls `GET /api/v1/operations/{endpoint_operation_id}` and
stores the returned safe diagnostic snapshot rather than a raw agent result.

## API and ownership rules

| Surface | Owner | Contract |
| --- | --- | --- |
| `GET /api/v1/devices/{device_id}/capabilities` | Endpoint Platform | `devices.read`; safe availability only |
| `POST /api/v1/devices/{device_id}/operations` | Endpoint Platform | `operations.create`; route device and verified ServicePrincipal only |
| `GET /api/v1/operations/{operation_id}` | Endpoint Platform | `operations.read`; same service client only |
| `/agent/v1/connect` | Endpoint Platform | Gateway WSS agent transport; no Helpdesk fields |

An operation's public lifecycle is `queued → delivered → acknowledged →
running → succeeded|failed|expired` (with server-supported `canceled` where
applicable). ContextCollection and Command remain private implementation
records; explicit mappings prevent their internal states becoming API terms.

## Delivery and result flow

1. Endpoint validates the active route device, capability observation, bounded
   request, and required idempotency key.
2. One transaction creates the EndpointOperation, private diagnostic
   ContextCollection and `endpoint.operation_created` audit event.
3. Only `CommandService` serving `/agent/v1/connect` materializes and commits
   the private command/delivery before it writes the WSS frame. HTTP command
   pull intentionally excludes endpoint-operation collections.
4. The neutral runtime validates the typed `GatewayCommandV1` and runs the
   bounded diagnostic collector. It receives only `reason`, server-generated
   requested-by identity, operation/command correlation, deadline and
   idempotency key—not Helpdesk correlation.
5. ACKs and terminal results atomically update private command/collection and
   the operation. The server validates device/session/command ownership,
   result sequence and digest, validates `DeviceContextDiagnosticV1`, redacts
   the excerpt, persists the ContextSnapshot, then emits result ACK after the
   commit.

Offline operations remain `queued`; they never fall back to
`/agent/v1/gateway/commands/next`. Server-controlled expiry makes them
`expired`.

## Implementation and acceptance record (2026-08-18)

- The public contracts are `EndpointOperationCreateV1`,
  `EndpointOperationV1`, `EndpointDiagnosticResultV1`, and
  `EndpointOperationStatusV1`; generated JSON Schema and the committed OpenAPI
  artifact are in `contracts/jsonschema/` and
  `contracts/openapi/endpoint-platform-v1.yaml`.
- Alembic revision `0014_endpoint_operations` follows
  `0013_runtime_session_heartbeat`. Its upgrade adds `endpoint_operations` and
  reciprocal private collection ownership constraints; its downgrade removes
  those constraints, table and private `context_collections.operation_id` in
  reverse order. It was not applied to any remote database for this package.
- The routes are included only when `ENDPOINT_OPERATIONS_API_ENABLED=true`.
  The default is false. The capability route requires `devices.read`; creation
  requires `operations.create`; reads require `operations.read` and the same
  stable ServiceClient identity, allowing credential rotation without
  cross-client reads.
- The supported profile is only `diagnostic_v1`. Safe result projection uses
  the stored operation reason and the validated ContextSnapshot, allows only
  bounded process name/state fields, and centrally redacts diagnostic excerpt
  secrets. Raw transport data is neither stored in the public operation
  projection nor returned to Helpdesk.
- Local operation tests cover creation/replay, ownership, expiration,
  migration shape and route/OpenAPI behavior. Gateway tests cover WSS-only
  selection, committed-before-send delivery, ACK/result ownership and digest
  checks, server-side deadlines, terminal state synchronization, and result
  ACK only after the transaction commits.

## Non-goals and excluded legacy paths

- No generic `run_tool`, shell, PowerShell, Python, executable path, URL,
  service name or free-form command reaches Endpoint Gateway.
- No Helpdesk ticket/requester/queue/status/event fields occur in a WSS
  payload.
- No production, database, Nginx, systemd, rollout or test-agent change is
  part of this package.
