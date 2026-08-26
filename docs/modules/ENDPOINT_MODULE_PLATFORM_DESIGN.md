# Endpoint Module Platform v1 — Design

## Status and baseline

This document records the Phase 0 audit and the target architecture for the
Endpoint-owned module platform. The Endpoint baseline is commit
`90261822b6abb77ec5ee4e9ed8a9c5178d39e9bb`; the Helpdesk baseline is
`62b734ddf5b65a9978524c1c0af31bdf9ad53d2d`.

The current Endpoint operation path is deliberately narrow:

- `endpoint_contracts/commands.py` accepts the fixed context capabilities;
- `pc_agent/runtime/command_executor.py` delegates only to the context
  collection executor;
- `endpoint_server/operations/service.py` owns persisted, idempotent parent
  operations for `context.diagnostic.collect`;
- `endpoint_server/gateway/command_service.py` owns WSS delivery and terminal
  result recording.

It is a suitable bounded control-plane foundation, but it does not yet expose
network primitives, a module catalog, recipe validation, or module operation
steps.

## Ownership boundary

Endpoint Platform is the only source of truth for module definitions, immutable
versions, recipes, validation/publication/compatibility, endpoint operations,
child commands, result lifecycle, and rollout state. A recipe is expanded on
the Endpoint server; an agent receives one concrete, typed primitive command.

Helpdesk owns the browser, its RBAC and audit actor, ticket and diagnostic
models, a local facade operation, `EndpointOperationLink`, and safe evidence.
It never sends ticket data, actor identity, browser tokens, recipe source, or
service credentials to an agent. The browser never receives an Endpoint token.

## v1 execution model

1. A privileged Helpdesk service client creates a ModuleDefinition and an
   immutable ModuleVersion through the typed Endpoint API.
2. Endpoint validates an `EndpointRecipeModuleSpecV1` against its published
   capability catalog. A `validated` version may create a lab-only parent at
   `POST /api/v1/modules/{module_key}/versions/{version}/lab-operations/{device_id}`.
   The regular module-operation path remains `published`-only.
3. Gateway WSS latches the authenticated agent's declared platform when it
   first delivers that lab parent. Endpoint accepts a lab test only from the
   terminal, successful lab parent and its terminal typed child steps; the
   record endpoint never accepts a caller-supplied platform or raw result.
4. `POST /api/v1/modules/{module_key}/versions/{version}/accept-labs` changes
   a version to `lab_accepted` only after each declared platform has that
   immutable Endpoint-derived evidence. Publication then requires
   `lab_accepted`. A version is never updated in place.
5. Helpdesk creates one local facade operation and durable link, commits, then
   its reconciler requests one Endpoint parent module operation.
6. Endpoint expands the recipe sequentially. Each step becomes exactly one
   WSS command for the target device and records a terminal typed result.
7. Endpoint aggregates bounded step summaries. Helpdesk projects exactly one
   `endpoint.module.recipe` DiagnosticEvidence and does not alter ticket
   status.

## Recipe safety contract

`endpoint_recipe_module_v1` permits at most eight unique sequential steps.
Only published `safe_read` built-ins can be referenced. Parameters bind only a
declared input or a JSON literal; output chaining, loops, branching,
interpolation, expressions, imports, code, shell, PowerShell, URL,
filesystem/executable paths, dependencies, and agent-side recipe installation
are rejected.

The first recipe is `network.basic.check@1.0.0`: `dns.resolve`,
`network.ping`, then `tcp.connect`. Its `target` and `port` originate from
declared inputs, not from Helpdesk ticket data.

## Lifecycle and rollout

ModuleVersion lifecycle states are `draft`, `validation_failed`, `validated`,
`lab_accepted`, `published`, `deprecated`, and `revoked`. The service rejects
`draft -> published`, `validation_failed -> published`, and reactivation of a
deprecated/revoked version. Corrections create a new version.

All feature flags default closed:

- Endpoint: `ENDPOINT_MODULE_PLATFORM_ENABLED=false`,
  `ENDPOINT_MODULE_EXECUTION_ENABLED=false`, and
  `ENDPOINT_NETWORK_PRIMITIVES_ENABLED=false`.
- Helpdesk: `ENDPOINT_MODULE_PORT_MODE=unavailable`,
  `MODULE_WORKBENCH_AUTHORITY=legacy`,
  `ENDPOINT_MODULE_EXECUTION_MODE=disabled`, and
  `LEGACY_MODULE_EXECUTION_ENABLED=true`.

No automatic or error-triggered fallback is allowed. `endpoint_shadow` is
read-only catalog comparison; `endpoint` executes endpoint-native modules only;
`legacy` preserves the current module runtime.

## Required Endpoint changes

PR-EP1 adds fixed network DTOs, bounded platform adapters, a fail-closed
target policy, explicit capability registry entries, agent capability reporting,
and capability projection. It does not add recipes, modules, Helpdesk routes,
or generic execution.

PR-EP2 adds `endpoint_contracts/modules.py`, the `endpoint_server/modules/`
bounded context, database migrations, validation/lifecycle/audit, recipe
engine, compatibility projection, parent/step operations, module API scopes,
and tests. It consumes only the PR-EP1 typed built-ins.

PR-EP3 makes the existing lab gate executable: it adds scoped typed lab
operation, live-test-record and lab-acceptance routes; validates that all lab
evidence belongs to the exact terminal Endpoint parent; and stores the
Gateway-observed platform privately with that parent before accepting it.

## Audit findings and migration rule

The Helpdesk Workbench currently stores/reconstructs `user_function_body`,
generates Python module packages, preflights archives, and dispatches through
legacy tool and agent paths. Existing package/runtime sources include
`system`, `inventory`, `diag_logs`, `screen`, `input`, `presence`, and the
recipe-runner package. Those paths remain legacy-only in v1; no Python source
is imported or converted automatically. The authoritative per-module
classification is the Helpdesk migration matrix.

## Non-negotiable guards

- No dynamic imports, `getattr` dispatch, executable paths, script bodies,
  generic `run_tool`, or generic `invoke` in the Endpoint agent executor.
- Network probes are denied unless both server and agent independently accept
  the target policy. A policy disagreement is a stable policy error.
- Module command/result rows are private Endpoint implementation details.
- Helpdesk `DeviceOutbox`, `ToolService`, legacy WebSocket, and module package
  installation must have zero use for endpoint-native module execution.
- No production deployment, production credentials, TLS bypass, or DB
  downgrade is part of this work.

## Verification strategy

Each PR adds focused negative tests before implementation and runs its stated
contract, operations, gateway, runtime, primitive, architecture, packaging,
and compile checks. Cross-repository acceptance uses real Endpoint/Helpdesk
applications, PostgreSQL, Gateway WSS, and a protocol-compatible agent client;
a fake JSON provider is insufficient. Staging acceptance remains a separate,
post-merge ALT and Windows canary with a verified rollback.
