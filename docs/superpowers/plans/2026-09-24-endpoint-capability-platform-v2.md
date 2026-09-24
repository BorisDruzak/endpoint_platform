# Endpoint Capability Platform v2 Implementation Plan

> **For agentic workers:** Implement task-by-task with the existing Endpoint test and release workflow. This plan is executed inline in the current task.

**Goal:** Add fixed, typed, bounded System, Process, Service, Printer, Software, Event Log and Filesystem Agent capabilities to the existing Module Platform.

**Architecture:** Extend `MODULE_CAPABILITY_REGISTRY` and its existing Gateway/Module/Operation path. Bind each descriptor to a strict parameter/result DTO and fixed platform handler. Derive executable surfaces from the registry wherever possible and guard remaining physical DB migration state with a test.

**Tech Stack:** Python 3, Pydantic 2.12.5, psutil 7.2.2, FastAPI, SQLAlchemy/Alembic, React/TypeScript, Windows and ALT Linux, existing Agent release pipeline.

**Spec:** `docs/architecture/endpoint-capability-platform-v2.md` and the user-supplied Capability Platform v2 specification.

## Global constraints

- Keep the six existing capability IDs and contracts additive and working.
- New capability group flags default to false and are not enabled by a migration.
- No arbitrary shell, command, path, channel, service action or write capability.
- Each Agent handler has explicit supported platforms and bounded time, items, text and aggregate output.
- Agent runtime release follows the immutable manifest and existing Windows/ALT update pipeline.
- Module results remain in existing Operation/Evidence retention and audit flows.

## Review focus

- A just-disconnected or old Agent must be incompatible before Module Lab/Run dispatch.
- An unavailable print system with no installed printers must return a safe empty result, not a fabricated printer.
- A very large process/software/event inventory must stop at the DTO and 64-KiB Gateway limits.
- A supplied path, service or event channel outside the fixed catalog must fail during recipe validation and again at the Agent.
- A migration upgraded from 0027 must accept every published executable registry capability in `ModuleOperationStep`.

## Tasks

### 1. Registry and contract surface

**Files:** `endpoint_contracts/capabilities.py`, `endpoint_contracts/modules.py`, `endpoint_contracts/operations.py`, `endpoint_contracts/commands.py`, `endpoint_contracts/gateway_ws.py`, new `endpoint_contracts/capability_platform_v2.py`, `tests/contracts/`.

- [ ] Add strict parameter and result DTOs for every v2 ID, with exact discriminators, bounded strings and lists, `extra=forbid` and no generic public `dict[str, Any]` result.
- [ ] Extend descriptor metadata with backend Russian name/category, risk, fixed policy, platform, version, flag, timeout and item cap. Preserve existing contract shape where clients depend on it.
- [ ] Derive catalog length, Gateway command schema and public operation availability from registry keys/DTOs; keep legacy non-Module command IDs explicit.
- [ ] Test invalid extra fields, enums, over-limit values, schema discriminators, result bounds and old DTO compatibility.
- [ ] Regenerate JSON Schema/OpenAPI with the repository generator and run its `--check` mode.

### 2. Persistence and drift guard

**Files:** `endpoint_server/db/models/operations.py`, new `endpoint_server/db/migrations/versions/0028_capability_platform_v2.py`, `tests/server/test_migrations.py`, `tests/modules/test_module_operation_models.py`.

- [ ] Add a forward-only PostgreSQL migration replacing `ck_endpoint_operation_steps_capability` with the complete v2 ID list; preserve existing step rows.
- [ ] Compare registry keys to model check, migrated SQL check, Gateway support, Agent dispatcher, Hello advertised set and typed Module result union in one regression test.
- [ ] Exercise a fresh database upgrade and an insert for a new step ID.

### 3. System and Process

**Files:** new `pc_agent/primitives/system_process/` handlers/dispatch, Agent runtime dispatcher, Hello, tests under `pc_agent/tests/primitives/`.

- [ ] Use psutil to collect one resource snapshot and bounded process summaries with only approved fields.
- [ ] Enforce exact plain-text process name matching, no regex, and terminate enumeration at the cap/deadline.
- [ ] Test Windows/ALT adapter branches, inaccessible processes, large lists and payload validation through AgentResult.

### 4. Service and Printer

**Files:** new fixed service catalog and `pc_agent/primitives/printer/` handlers/dispatch, platform helpers, tests.

- [ ] Preserve `system.service_status`; add fixed logical service list/status, including the platform print service.
- [ ] Enumerate printers through fixed Windows/CUPS APIs or commands; validate printer identifier against the local bounded enumeration.
- [ ] Aggregate print jobs without retaining owner/title/path fields; test zero printers, paused/offline/error flags, oversized queues and privacy exclusions.

### 5. Software

**Files:** new `pc_agent/primitives/software/` handlers/dispatch, platform helpers and tests.

- [ ] Read fixed Windows machine uninstall views and fixed ALT RPM query; emit only safe bounded metadata.
- [ ] Deduplicate and sort products before list/find, enforce caps and plain text matching, and test missing package manager and malformed records.

### 6. Filesystem

**Files:** new `pc_agent/primitives/filesystem/` path catalog, handlers/dispatch and tests.

- [ ] Enumerate local volumes only and expose fixed volume keys/bytes/type.
- [ ] Map the three logical Endpoint path keys to fixed platform paths; only runtime manifest supports metadata.
- [ ] Reject arbitrary path keys and symlink/reparse escape; test no contents or resolved path is returned.

### 7. Event Log

**Files:** new `pc_agent/primitives/eventlog/` profile catalog, handlers/dispatch and tests.

- [ ] Implement fixed Windows channel profile queries with ≤60-minute lookback and ≤32 events; mark ALT unsupported until a journal privacy design is approved.
- [ ] Omit event messages, raw XML, binary payload, full Security log and unapproved channels.
- [ ] Test over-limit lookback/count, invalid profile/severity, malformed events and query timeouts.

### 8. Gateway, compatibility and server policy

**Files:** `endpoint_server/config.py`, `endpoint_server/operations/capabilities.py`, `endpoint_server/gateway/`, `endpoint_server/modules/`, tests under `tests/gateway/`, `tests/modules/`, `tests/operations/`.

- [ ] Add grouped default-false settings and use descriptor flag/policy to intersect Hello with runtime/platform/version.
- [ ] Validate exact typed result on Gateway ingress and reject >64-KiB messages and unsupported commands before dispatch.
- [ ] Report concrete version/platform/flag/effective-set incompatibility; verify old Agent never receives a new command.

### 9. Console and Workbench

**Files:** `endpoint_server/console/modules.py`, `endpoint_server/console/fleet.py`, `webapp/src/ModulesPage.tsx`, `webapp/src/FleetPages.tsx`, frontend tests.

- [ ] Serve Russian names/categories directly from the registry; remove the Console per-ID name map.
- [ ] Group Catalog cards by backend category and show risk, platform, minimum Agent version, parameter/policy details.
- [ ] Keep parameter-driven recipe forms, show effective connected capabilities on device detail and concrete incompatibility reason.
- [ ] Run frontend unit tests, browser E2E and production build.

### 10. Agent release and live Module acceptance

**Files:** `pc_agent/version.py`, generated immutable runtime manifest, existing release artifacts, `PLANS.md`, acceptance records.

- [ ] Select next free patch version from current remote release policy and build existing immutable runtime and update ZIP, with SHA-256 verification.
- [ ] Run focused and full Python tests, compileall, contract generation check, migration test, frontend checks and `git diff --check`.
- [ ] Use test ALT host and local Windows canary for real capability operations; keep each unverified platform explicit.
- [ ] Create four server-side acceptance recipes; validate, Lab, accept, publish, run and inspect 24-hour Evidence without changing Agent runtime between recipes.
- [ ] Roll out LAB → local IT Windows → small IT canary → pilot after gates, check WSS/Context/existing and new Modules/update/rollback, and record starting/ending SHA, artifact hashes and concrete production evidence in `PLANS.md`.
