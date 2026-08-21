# Helpdesk ↔ Endpoint Operations API v1 contract

## Status and authority

This is the jointly consumed integration specification for the first Helpdesk
Endpoint-operation vertical slice.  Endpoint Platform owns the normative wire
contract: the generated OpenAPI document at
`contracts/openapi/endpoint-platform-v1.yaml` and its JSON Schema artefacts
are authoritative.  Helpdesk is a consumer and may not add fields, infer
identity, or use runtime imports from this repository.

The repositories stay independently deployable.  A Helpdesk release records
the exact Endpoint provider commit in
`integration/endpoint_contract.lock.json`; it must validate only the published
OpenAPI/schema at that commit and its own HTTP adapter.  Cross-repository
Python imports are allowed only in the dedicated acceptance test.

## Required Operations API routes

The provider exposes exactly these consumer routes under `/api/v1`:

| Method | Route | Successful response |
| --- | --- | --- |
| `GET` | `/devices/{device_id}` | `200` device envelope |
| `GET` | `/devices/{device_id}/capabilities` | `200` versioned capabilities envelope |
| `POST` | `/devices/{device_id}/operations` | `201` create / `200` idempotent replay operation envelope |
| `GET` | `/operations/{operation_id}` | `200` operation envelope |

All successful payloads use `{"data": ...}` only.  An operation payload is
always nested as `data.operation` plus `data.result`.  `data.result` is null
for non-success states and non-null only for a succeeded operation with a
validated safe result.  No top-level `correlation_id`, `device`, or flattened
operation/result fields are permitted.

The device summary is `EndpointDeviceSummaryV1`: exact UUID `device_id`, a
bounded safe display name, the retirement flag, and nullable aware
`last_seen_at`.  It contains no hostname, IP, MAC, raw device context,
credential, transport, agent-session, or ticket data.  The capabilities
response has a literal `schema_version` and an exact `device_id`; every item
states only the fixed capability, its availability, WSS transport, read-only
risk, no-consent flag, and parameter-schema version.

## Correlation and service authentication

For every route above the consumer sends a syntactically valid
`X-Correlation-ID` request header.  Every normal successful response and every
provider error response includes `X-Correlation-ID` with the exact received
value.  It is a tracing value only: it is never used to authorize, scope, or
look up a service principal, device, operation, ticket, or user.

The value is not included in the JSON envelope.  The Endpoint operation model
does not carry Helpdesk ticket, actor, diagnostic-session, or Helpdesk
correlation data.  Provider-to-agent delivery likewise carries no Helpdesk
correlation/ticket payload.  Service authorization remains the Endpoint
service-bearer/scope check and operation ownership remains Endpoint-owned.

## Operation contract and delivery

The create request has the fixed `context.diagnostic.collect` capability and
the defined empty/safe parameter schema.  `Idempotency-Key` identifies an
Endpoint-owned service-client/device/request tuple and produces `201` once and
`200` on the exact replay.  A different request for the same key yields the
documented conflict response.

The public operation includes only Endpoint operation ID, exact device ID,
capability, lifecycle timestamps/status, and a safe-result availability flag.
The nested result contains the existing validated safe diagnostic projection
only.  `succeeded` without that safe result is a provider contract failure and
must not be represented as success to the consumer.

Endpoint delivery stays Gateway WSS-only.  It never uses a Helpdesk WebSocket,
Helpdesk DeviceOutbox, HTTP pull, or dual dispatch.  The headless agent receives
only the Endpoint command contract; Helpdesk identity/correlation fields are
not added to it.

## Helpdesk consumer requirements

`ExternalEndpointHttpAdapter` owns wire DTO parsing separate from the internal
`EndpointPort` DTOs.  Wire DTOs are strict (`extra=forbid`) and check exact
envelope keys, response header correlation, route/device/operation IDs,
literal schema versions, and nested operation/result structure before one-way
mapping to the internal safe projection.  Any extra field, schema drift,
missing/mismatched header, mismatched ID, or succeeded response without a safe
result fails closed as `invalid_projection`.

Before endpoint-mode readiness, Helpdesk calls
`EndpointDeviceReferenceService` to read and persist an exact verified Endpoint
device reference/safe snapshot.  Mapping is admin-created/managed through an
admin-only endpoint and is never derived from hostname, IP, MAC, browser input,
or a fallback resolver.

Migration 137 introduces caller-scoped local idempotency for the facade
operation.  The stored caller key is unique only within its trusted actor
scope; replays return the same local operation and a conflicting payload fails
closed.  Endpoint remote idempotency remains a distinct stable key derived
from the local operation, not a user key.

The reconciler processes one durable claim at a time, or renews that claim's
lease immediately before each remote request.  A single-claim exception is
isolated, recorded, and does not stop the runner.  Database state is committed
before local UI publication; publication failures are observable but never roll
back committed terminal state.  The terminal successful projection creates
exactly one `DiagnosticEvidence` keyed to the external operation reference.

Endpoint capability mode remains explicitly separate from the legacy runtime:
no automatic fallback, no dual dispatch, and no ToolService, Helpdesk
WebSocket, or DeviceOutbox path is permitted.

## Acceptance evidence

The cross-repository test runs the real `endpoint_server.main.create_app()`
and the real Helpdesk `ExternalEndpointHttpAdapter` against a temporary
database and test credentials.  It must not use a fake JSON HTTP server or
mock provider routes.  It proves all four reads/writes, `201` create/`200`
replay, operation read, correlation equality, strict projection rejection,
and negative responses.  Its vertical case continues through Gateway WSS and
a headless agent to one safe result and exactly one Helpdesk
`DiagnosticEvidence`, while proving no Helpdesk WebSocket/DeviceOutbox
dispatch occurred.

No production deployment, migration, credential change, process restart, or
agent rollout is part of this contract work.

## Provider release-gate evidence

The provider correlation middleware applies only to the four routes in the
required route table, matched by HTTP method and exact path shape. It does not
apply the Operations API correlation policy to other device routes, including
network-identity, context, or update surfaces. Router UUID validation remains
the route-layer responsibility.

`endpoint-operations-provider.yml` verifies this provider surface on pull
requests to `main`, pushes to `main`, and manual dispatches. For a relevant
change it runs the contracts, operations, and Gateway suites; checks generated
contract artifacts; compiles the provider and agent packages; and checks the
Git diff. The workflow uploads JUnit XML as the
`endpoint-operations-provider` artifact. It uses no production credential,
configuration, deployment, or agent rollout.
