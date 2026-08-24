# Windows Headless Diagnostic Canary v1 Design

**Status:** proposed; implementation is gated on this document's review.

## Goal

Provide reusable, fail-closed tooling for one Windows `context.diagnostic.collect`
staging canary. The tooling must prove that an immutable Windows installation,
the existing Endpoint Operations API and Gateway WSS complete one safe diagnostic
without Helpdesk data reaching the agent or legacy Helpdesk dispatch being used.

## Scope and ownership

Endpoint Platform owns the Windows MSI, `EndpointAgent` and
`EndpointAgentUpdater` services, enrollment, the device credential, Gateway
WSS, Endpoint operation lifecycle, and the bounded agent completion proof.
Helpdesk owns the ticket-facing local operation, `EndpointOperationLink`,
diagnostic session/step, `DiagnosticEvidence`, orchestration and evidence
reporting. The services communicate only through the established Endpoint
Operations API v1; there are no cross-repository Python imports or database
relationships.

The canary command payload remains a bounded Endpoint command containing only
`context.diagnostic.collect` and its permitted reason. It must not include a
ticket, requester, Helpdesk actor, queue, diagnostic session, idempotency key,
service credential, URL, executable or script.

## Endpoint Platform design

`tools/canary/Collect-WindowsAgentPreflight.ps1` will collect a redacted,
read-only JSON projection from an already installed Windows agent. It will read
only service metadata, immutable release metadata, file type/reparse state,
ACL summaries, certificate metadata, safe-status output and bounded network
facts. It will neither read credential/enrollment content nor create an
operation, start/stop a service, install software or perform enrollment.

`tools/canary/verify_installed_windows_agent.py` will strictly validate that
projection against the approved manifest. Validation fails closed for a missing
or incorrectly configured `EndpointAgent`, a non-fixed Program Files image,
wrong runtime child, selector/package mismatch, unsafe DACL, active updater,
HTTP pull/fallback, TLS/hostname failure, Helpdesk reference, missing WSS or
missing capability. A valid result is `READY`; all other outcomes carry safe
reasons only.

The existing runtime marker is emitted before result delivery and already has
the required bounded fields. The implementation will first make the Windows
service sink observable after execution. If the packaged service's current log
sink cannot provide one protected, bounded record, add a Windows-only protected
JSONL sink under the agent data root. It must use a fixed path, reject reparse
paths, retain a bounded number of records, rotate safely and never contain raw
results, parameters, URLs or credentials. This must not change Gateway wire
messages. Any runtime change increments `AGENT_VERSION`, updates immutable
release inputs and is built through the existing MSI pipeline only.

## Helpdesk design

The existing `endpoint_diagnostic_canary.py` becomes a manifest v2 orchestrator
with `preflight`, `map`, `execute`, `observe`, `verify`, `rollback-check` and
`report` commands. The v2 schema is exact (unknown fields rejected) and retains
read-only parsing of historical v1 ALT manifests. All command outputs are
redacted JSON, and only `--apply` permits `map` or `execute` after exact
staging approval and technical staging proof.

The orchestrator reuses existing admin mapping, support diagnostic, operation
and evidence projections. It does not add a canary business route or bypass
the Endpoint port/adapter. `execute` creates at most one request with one
durable caller idempotency key; recovery reads the existing state with the same
key and never generates a second key. `observe` and `verify` are read-only.
`rollback-check` proves an externally approved rollback but changes no
configuration itself. `report` writes only a secret-free summary and hashes.

## Staging and evidence gate

Before any mutable stage, the manifest and environment must agree on staging
hosts, device, ticket, change ID, exact Endpoint/Helpdesk revisions, database
revisions, Windows service/MSI/version/source revision and protected evidence
root. The tooling must also show that the Windows machine is dedicated and
non-production, with a recovery point, and that production hosts, databases
and units do not occur in the scope. The known test Windows host
`192.168.101.120` may be used only after this proof is recorded. Missing proof
terminates the run as `WINDOWS_CANARY_BLOCKED` before installation, enrollment,
mapping, flag changes or operation creation.

The evidence package is outside Git, protected, redacted and covered by
`SHA256SUMS`. It records only allowed identifiers and hashes. It never contains
credentials, claims, cookies, private keys, database URLs, raw logs, raw
results, ticket text or requester data. Acceptance documentation is written
only after a successful real canary and rollback; otherwise the corresponding
blocked or failed document is written.

## Verification

Endpoint tests cover each invalid Windows service, selector, MSI, ACL,
transport and evidence condition plus a valid `READY` fixture. Helpdesk tests
cover v1 compatibility, strict v2 validation, dry-run non-mutation, approval
matching, exactly-once execution/reconciliation, no-legacy deltas, rollback
non-mutation and report redaction. Existing operations, gateway, contract,
architecture, packaging, runtime and cross-repository suites remain required.

## Non-goals

No production action, migration/downgrade, customer machine installation,
mass rollout, arbitrary PowerShell/shell, Remote Assist, removal of legacy
Helpdesk transport or change to `/ws_ui` is included.
