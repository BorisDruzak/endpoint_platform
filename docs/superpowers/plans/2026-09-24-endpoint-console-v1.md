# Endpoint Console v1 Implementation Plan

> **For agentic workers:** Execute each phase with focused failing tests, implementation, verification, and an atomic Conventional Commit. Read the linked specification before changing a phase.

**Goal:** Deliver the Russian language Endpoint Platform operator console at `/admin` for the complete device lifecycle, without exposing service or agent credentials to browsers.

**Architecture:** FastAPI serves a locally built React/TypeScript/Vite bundle and `/api/admin/*` session authenticated facades. Facades reuse existing Endpoint domain services and return bounded safe DTOs. The single Gateway WSS, `/api/v1/*` service contracts, and existing storage remain authoritative.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, React, TypeScript, Vite, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-24-endpoint-console-v1.md`

## Baseline and decisions

- Starting `main`: `2995b06d3b45a26d39b6acc4129e5892b6c7c942`; GitNexus indexed the same commit.
- Agent version is read from `pc_agent/version.py` at build time; current baseline is `3.2.63`.
- Alembic head is `0021_request_claim_envelopes`. Never edit historic revisions.
- There is no canonical frontend stack. `/admin/enrollment` is an English, inline HTML/JS page. `/api/admin/session` supplies the existing session cookie and CSRF token.
- Admin reads use `require_admin`; mutations use existing scope gates or new narrow admin scopes. `/api/v1/*` continues to require service credentials independently.
- `ModuleOperationStep` and migration 0017 allow three primitives while the canonical registry exposes six. Repair this before Module Workbench.
- The production runbook currently archives only Python server assets. Add the built bundle to the release archive and verify Nginx/FastAPI fallback routing before deployment.

## Global constraints

- All operator text, including errors and empty states, is Russian; dates use `ru-RU`. Protocol identifiers may appear as secondary diagnostic text.
- Never return service tokens, agent credentials, claims, capabilities, raw command/result payload, private certificates, or unsanitized audit details to the browser.
- Lists are paginated and bounded; device and dashboard projections use set based queries, without per-row context or update queries.
- Reuse existing enrollment, context, update, operation, module, audit, session, CSRF, and feature gate lifecycles.
- Preserve published `/api/v1/*` contracts and the single `/agent/v1/connect` transport.
- Production deployment follows backup, disk, migration, release, strict TLS, runtime, and rollback gates in the repository runbook.

## Review focus

- An expired or revoked session must fail both page and API access; cover in Phase 1 ASGI tests.
- A stale context snapshot must be marked stale and retain its collection timestamp; cover in Phase 2 projection and browser tests.
- Concurrent context refresh clicks must preserve collection idempotency; cover in Phase 2 API tests.
- A partial rollout with failing targets must keep accurate counts and action availability; cover in Phase 4 tests.
- An unsupported module capability or fabricated lab result must fail server side; cover in Phase 6 negative tests.

## Phase 0: Canonical module step persistence

**Files:** `endpoint_server/db/models/operations.py`, new `endpoint_server/db/migrations/versions/0022_module_step_capabilities.py`, `tests/modules/test_module_operation_models.py`, `tests/server/test_migrations.py`, `PLANS.md`.

**Deliverable:** Every executable canonical primitive is valid in the model and PostgreSQL CHECK constraint; regression tests detect catalog drift.

- [ ] Add a failing model test comparing the CHECK allowlist with `MODULE_CAPABILITY_REGISTRY` and a migration test for a forward-only 0022 revision.
- [ ] Run `python -m pytest tests/modules/test_module_operation_models.py tests/server/test_migrations.py -q` and confirm the new assertions fail.
- [ ] Derive the model CHECK from a closed registry tuple and add a frozen, additive Alembic replacement of `ck_endpoint_operation_steps_capability`.
- [ ] Run focused model and migration tests, including a real local PostgreSQL migration when `ENDPOINT_TEST_POSTGRES_URL` is available; run `git diff --check`; commit only Phase 0 files.

## Phase 1: Console foundation

**Files:** new `webapp/package.json`, `webapp/src/app/*`, `webapp/src/shared/*`, `endpoint_server/console/routes.py`, `endpoint_server/main.py`, `deploy/server/PRODUCTION_RUNBOOK.md`, console ASGI and frontend tests.

**Deliverable:** `/admin/login`, `/admin`, shared layout/navigation, Russian status/error handling, same session/CSRF client, and static production bundle served without Node in production.

- [ ] Test page access, invalid session, login/logout, cookie-only service API denial, CSRF, asset cache policy, and SPA deep links against the real ASGI app.
- [ ] Build Vite with local assets only. Boot the browser from a session bootstrap endpoint; retain CSRF only in memory. Add keyboard and focus states.
- [ ] Verify typecheck, unit tests, production build, backend tests, and login/dashboard browser smoke. Commit foundation separately.

## Phase 2: Fleet, devices, context, changes

**Files:** new `endpoint_server/console/fleet.py`, `endpoint_server/console/device_routes.py`, `webapp/src/features/devices/*`, `webapp/src/features/context/*`, projection/API/browser tests.

**Deliverable:** Aggregated dashboard; paginated/filterable device list and detail; overview, context, semantic history, refresh, and cross-links.

- [ ] Define typed admin DTOs and query-count tests before implementation. Batch current snapshot, presence, version, session, and update state joins.
- [ ] Reuse context collection service and semantic diff; expose only normalized safe projections and bounded history.
- [ ] Verify filters, offline/stale/empty/error states, idempotent refresh, privacy, and browser navigation. Commit backend and frontend as reviewable linked changes.

## Phase 3: Installer and enrollment

**Files:** console enrollment routes, optional immutable Setup release model plus its own migration, `webapp/src/features/enrollment/*`, enrollment tests and runbook.

**Deliverable:** Installer metadata/download, lifecycle explanation, campaign management, request queue/detail, approve/deny, and one canonical `/admin/enrollment` route.

- [ ] Inspect existing Setup sidecars and artifact ownership. Add a metadata registry only if sidecars cannot provide durable trusted projection; never put binary in PostgreSQL.
- [ ] Reuse existing campaign/request policy and redacted evidence; do not expose claim envelopes or receipts.
- [ ] Verify signed versus unsigned labels, policy selection, decisions, registered-device link, CSRF, and browser flow. Commit independently.

## Phase 4: Releases and updates

**Files:** `endpoint_server/updates/admin_routes.py` or narrow read module, `webapp/src/features/updates/*`, update API/browser tests.

**Deliverable:** Paginated immutable build and rollout reads, target counts/detail, create canary/bulk, pause/resume, rollback as a new rollout, and device update history.

- [ ] Add failing scope, secret-exclusion, pagination, and target-count tests. Reuse update service transitions and its canary prerequisite.
- [ ] Show target preview and explicit confirmation. Preserve auto-completion behavior and immutable manifests.
- [ ] Verify update suites and browser workflow; commit separately.

## Phase 5: Operations

**Files:** console operation routes, `webapp/src/features/operations/*`, operation tests.

**Deliverable:** Bounded global/device operation history, filters, details, safe result and module step projections, supported queued cancellation.

- [ ] Reuse existing operation projection/redaction and feature gates. Test ownership, pagination, no raw payload, and status timing.
- [ ] Verify operation and gateway tests plus browser drilldown; commit separately.

## Phase 6: Module Workbench

**Files:** console module routes, `webapp/src/features/modules/*`, module contract/service/API/browser tests and Module Platform docs.

**Deliverable:** Server supplied capability catalog, all versions, declarative recipe editor, validation, real lab execution/evidence, accept/publish/deprecate, and compatible device execution.

- [ ] Test capability allowlist, at most eight inputs/steps, input/literal bindings, platform/version/feature compatibility, and scope gates.
- [ ] Reuse current module lifecycle services. Never accept browser authored live-test evidence; expose Endpoint derived records only.
- [ ] Verify no Agent version or filesystem recipe change, typed command delivery, unsupported capability rejection, lifecycle gates, and browser authoring-to-publish flow. Commit separately.

## Phase 7: Audit and cross-links

**Files:** console audit routes, `webapp/src/features/audit/*`, audit tests.

**Deliverable:** Read-only, paginated, filtered, sanitized audit events with links to existing devices, operations, rollouts, enrollment, and modules.

- [ ] Add failing filter/pagination/redaction tests and retain immutable audit storage.
- [ ] Verify audit suites and browser filters; commit separately.

## Phase 8: Release acceptance

**Files:** deployment/runbook, architecture docs, `PLANS.md`, browser E2E, Russian text guard, production assets.

**Deliverable:** Full security, contract, migration, browser, and production verification; `/admin` becomes canonical operator entry.

- [ ] Run focused and full relevant backend suites, contract generator `--check`, architecture guards, compileall, frontend typecheck/unit/build, browser E2E on real backend, and `git diff --check`.
- [ ] Validate release archive contains web assets; backup production DB, verify capacity and rollback marker, migrate/deploy, and verify service, worker, Nginx, strict hostname/CA TLS, login, navigation, and core browser flows.
- [ ] Record starting/ending SHA, branch, migration head, exact routes, migrations, checks, and unaccepted fleet risks. Do not claim production ready before all gates pass.
