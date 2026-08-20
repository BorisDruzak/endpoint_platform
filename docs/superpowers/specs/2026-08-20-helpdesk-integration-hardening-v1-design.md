# Helpdesk–Endpoint Integration Hardening v1 Design

## Status and baselines

Approved planning specification. It governs two independent repositories and is
not a deployment instruction.

| Repository | branch | planning baseline |
| --- | --- | --- |
| `BorisDruzak/endpoint_platform` | `codex/helpdesk-integration-hardening-v1` | `94da3b61faa2761b093a10e09dd69d54149da9a4` |
| `BorisDruzak/helpdesk` | `codex/endpoint-integration-hardening-v1` | `de1bf33d68646f8d86051016bf806dacf1d311cb` |

Endpoint OpenAPI is the canonical wire contract. Helpdesk is a strict consumer;
neither production repository imports the other at runtime. A cross-repository
test may import Endpoint only from its explicitly supplied test checkout.

## Outcome

The supported path is exactly:

```text
Helpdesk facade operation → Endpoint Operations API v1 → Gateway WSS
→ headless agent → safe terminal result → one Helpdesk DiagnosticEvidence
```

Endpoint remains the owner of agent delivery, operation lifecycle, and service
authorization. Helpdesk owns ticket authorization, verified device association,
local facade lifecycle, audit, and evidence. `X-Correlation-ID` is tracing
metadata only: it is never authorization input, is never stored in a JSON
envelope, and Helpdesk ticket/actor/session data never reaches an agent.

## Canonical HTTP contract

Routes are:

```text
GET  /api/v1/devices/{device_id}
GET  /api/v1/devices/{device_id}/capabilities
POST /api/v1/devices/{device_id}/operations
GET  /api/v1/operations/{operation_id}
```

All routes accept an optional valid `X-Correlation-ID`, and all normal/error
responses include the identical value when it was supplied. The provider
accepts only ASCII `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`; missing remains
allowed only where the route already permits it, while malformed values are
rejected with a safe `422` and are not reflected or logged verbatim.

Provider additions are `EndpointDeviceSummaryV1`, a device read route, a
versioned capabilities response, and the response header rule. Operation
responses retain their existing nested shape: `data.operation` plus
`data.result`. Provider schemas, OpenAPI, generated artifacts and contract
fixtures change together. WSS is the sole delivery transport.

The Helpdesk adapter has separate external wire DTOs and internal `EndpointPort`
DTOs, both strict (`extra=forbid`). It verifies HTTP status, envelope/schema
version, allowed fields, IDs, echoed correlation and nested operation/result
projection before translating to internal safe values. It rejects extra fields,
schema drift, mismatched IDs/correlation, and `succeeded` states without a safe
result. It does not construct a fallback request or a second dispatch.

## Locked provider and reproducible acceptance

`integration/endpoint_contract.lock.json` is the consumer's immutable
dependency declaration. It records `provider_repository`, exact immutable
`provider_commit`, `openapi_path`, and the SHA-256 of the checked-in OpenAPI
bytes. A validator rejects a checkout unless its `HEAD` equals the lock and the
OpenAPI digest equals the lock. The Helpdesk branch first points at the Endpoint
provider feature tip; after the Endpoint PR merges, a final Helpdesk commit
updates it to the Endpoint merge SHA and its identical OpenAPI digest.

The test-only provider root is supplied only as `ENDPOINT_PLATFORM_REPO`.
Without it, the cross-repository module is skipped during normal local pytest;
there is no author path, fake JSON server, or source-tree guessing. GitHub CI
checks out the lock's normal public/readable GitHub repository with
`actions/checkout` and its ordinary `GITHUB_TOKEN`; it needs no additional
secret. If repository visibility cannot support that checkout, CI must fail at
the explicit checkout preflight rather than silently using a fake or cached
provider.

The acceptance stack creates Endpoint's real `endpoint_server.main.create_app()`
and Helpdesk's real `ExternalEndpointHttpAdapter`, temporary provider database
and temporary Helpdesk PostgreSQL database, service credential, and real WSS
test agent. It proves device/capability reads, `201` create, `200` replay,
operation read, strict/negative correlation and schema projections, then the
full vertical flow and exactly one `DiagnosticEvidence`.

## Helpdesk state safety

Verified mapping precedes readiness. An administrator supplies an exact Endpoint
device reference, never hostname, IP, or MAC. Helpdesk reads that exact device,
rejects a retired device, persists only a redacted immutable snapshot, and
audits the successful mapping. Idempotent equal replay produces no empty audit
event. Replacement requires `replace=true`, the expected previous reference,
and a bounded non-control-character reason; verification happens before the
short locked persistence transaction and the ticket is rechecked while locked.
Unauthorized actors receive `401`/`403`; a retired device gets the safe `409`
code `ENDPOINT_DEVICE_RETIRED` and leaves no mapping.

Migration `137` is additive and is not rewritten. It establishes
actor-scoped caller idempotency: the same caller and canonical request identity
return the same facade operation, while a semantic mismatch conflicts. The
idempotency key is not a ticket/agent correlation and is never delivered to the
agent.

The reconciler owns each lease only until the immediately following remote call.
It claims one item at a time, or renews/rechecks its lease immediately before
that call. Each claim is isolated. An unexpected per-claim exception writes only
a safe failure code, increments bounded attempts, releases the lease and sets a
bounded next retry; it creates neither evidence nor legacy dispatch. Stale claims
make no state change. A runner-level unexpected error is safely logged and
retries after bounded delay rather than terminating. A UI publication failure is
post-commit only: it cannot roll back committed state or reissue a remote call.

## Invariants and exclusions

- Endpoint capability code must not use Helpdesk `ToolService`, Helpdesk
  WebSocket, `DeviceOutbox`, or a legacy agent fallback; tests prove this by
  making those paths fail if called.
- Endpoint never sends Helpdesk ticket, requester, actor, diagnostic-session,
  correlation, or service credential data through Gateway WSS to the agent.
- Existing migrations and the old Helpdesk agent runtime remain intact.
- No production deploy, migration, credential/TLS/configuration mutation,
  restart, rollout, or force-push is part of this work.

## Completion evidence

Provider contract checks regenerate artifacts without diff. Consumer CI validates
the lock and passes the true cross-repository acceptance suite. Focused mapping,
adapter, lifecycle, reconciler and import-boundary tests pass. The final report
records both starting/ending SHAs, branches, provider/consumer PRs and commits,
new schemas/routes, migration 137, retry/lease and mapping semantics, exact
commands/results, one-evidence E2E proof, absence of legacy dispatch, remaining
risks, and an explicit statement that this hardening work changed no production
system.
