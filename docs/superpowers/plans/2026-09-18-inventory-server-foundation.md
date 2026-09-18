# Inventory Server Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add inventory/session profiles, correct presence projections, and expose the strictly typed safe service API without changing the sole Agent WSS transport.

**Architecture:** `endpoint_contracts` defines additive discriminated envelopes which flow through the existing capability-to-collection-to-snapshot pipeline. The context projection remains the single raw-data boundary; routes and SDK consume only validated safe projections. Presence reads server-written session timestamps and never agent-reported time.

**Tech Stack:** Python 3.12, Pydantic v2 strict models, FastAPI, SQLAlchemy async, pytest, httpx, setuptools.

**Spec:** `docs/superpowers/specs/2026-09-18-inventory-grade-telemetry-design.md`

## Global Constraints

- Keep `/agent/v1/connect` as the only Agent realtime endpoint; no `web_ovpn` Agent WSS, Agent credentials, raw payloads or database access.
- Preserve `baseline_v1`, `health_v1`, `network_v1`, their strict `extra=forbid` wire models, intervals and existing capability names.
- All `inventory_v1` technical fields are bounded and optional; unavailable is null/empty plus a safe warning, never a fabricated fact.
- `last_seen_at` is `DeviceSession.last_seen_at` with `created_at` only as a null fallback; `online` is server-calculated from an unclosed session and presence TTL.
- Service-facing profiles remain gated by `devices.read` / `context.read`; collection uses only `context.collect` and the existing idempotent request path.
- No production deployment, database migration execution, Agent rollout, web_ovpn modification, credential creation, or non-HTTPS verification is in scope.

---

### Task 1: Add additive Inventory and Session contracts

**Files:**
- Modify: `endpoint_contracts/context.py:8-150`
- Modify: `endpoint_contracts/__init__.py`
- Test: `tests/contracts/test_context_contracts.py`

**Interfaces:**
- Produces: `ContextProfileV1` includes `inventory_v1` and `session_v1`; `DeviceContextInventoryV1` and `DeviceContextSessionV1` validate `DeviceContextEnvelopeV1` payloads.
- Consumes: `ContractModelV1` strict configuration and the existing warning vocabulary.

- [ ] **Step 1: Write the failing contract tests.** Add an `inventory_v1` payload with nullable hardware, bounded empty device lists, and `mac-aabbccddeeff`; add a `session_v1` payload with `current_user_login` and `interactive_session_present`; assert that an unexpected `token` field or an invalid MAC raises `ValidationError`.

    def test_inventory_context_accepts_mac_interface() -> None:
        envelope = DeviceContextEnvelopeV1.model_validate(inventory_payload)
        assert envelope.profile == "inventory_v1"

- [ ] **Step 2: Run the targeted contract tests.** Run `python -m pytest tests/contracts/test_context_contracts.py tests/contracts/test_contract_models.py -q`. Expected: FAIL because profiles and section models do not exist.

- [ ] **Step 3: Write the minimal strict models.** Extend `ContextProfileV1`, `ContextSectionsV1`, `_PROFILE_SECTION_MODELS` and exports. Define optional bounded system, hardware, BIOS, baseboard, memory-module, physical-storage and interface models, with only the stated normalized media/bus/RAM/link-state literals. Define separate session fields and retain all existing classes unchanged.

    ContextProfileV1 = Literal["baseline_v1", "health_v1", "network_v1", "diagnostic_v1", "inventory_v1", "session_v1"]

- [ ] **Step 4: Run contract verification.** Run `python -m pytest tests/contracts -q`. Expected: PASS; old profile fixtures remain valid, while extra fields and invalid values fail.

- [ ] **Step 5: Commit.** Stage only contract files and run `git commit -m "feat(context): add inventory and session contracts"`.

### Task 2: Correct safe presence projections and guard the WSS surface

**Files:**
- Modify: `endpoint_server/context/routes.py:48-285`
- Modify: `endpoint_server/context/service.py`
- Test: `tests/context/test_service_api.py`
- Create: `tests/gateway/test_ws_inventory_boundary.py`

**Interfaces:**
- Produces: devices and identity-feed responses include `online: bool`; all safe profile listings allow inventory/session snapshots.
- Consumes: `DeviceSession.last_seen_at`, configured presence TTL, `require_service_scope`, and `snapshot_projection`.

- [ ] **Step 1: Write failing API and WSS tests.** Seed an unclosed session where `created_at` is old but `last_seen_at` is fresh, then assert list, identity-feed and context all return the fresh timestamp and `online: true`; seed a closed or TTL-expired session and assert false. Assert registered websocket paths are exactly `{ "/agent/v1/connect" }`.

- [ ] **Step 2: Run the tests.** Run `python -m pytest tests/context/test_service_api.py tests/gateway/test_ws_inventory_boundary.py -q`. Expected: FAIL because routes select `created_at`, return no `online`, and no boundary test exists.

- [ ] **Step 3: Implement one presence query helper.** Use `coalesce(DeviceSession.last_seen_at, DeviceSession.created_at)` for ordering and output; carry `closed_at` to the projection and compute `online` from the injected/configured server time and TTL. Reuse this helper in all three projections. Do not add a websocket router, decorator or redirect.

- [ ] **Step 4: Verify API/Gateway behavior.** Run `python -m pytest tests/context/test_service_api.py tests/gateway/test_ws_route_asgi.py tests/gateway/test_ws_reconnect.py tests/gateway/test_ws_inventory_boundary.py -q`. Expected: PASS.

- [ ] **Step 5: Commit.** Stage only these route/service/test files and run `git commit -m "fix(context): project heartbeat last seen state"`.

### Task 3: Extend collection lifecycle, semantic tracking and bootstrap refresh

**Files:**
- Modify: `endpoint_server/context/ingestion.py:23-250`
- Modify: `endpoint_server/context/canonicalize.py`
- Modify: `endpoint_server/context/diff.py`
- Modify: `endpoint_server/context/scheduler.py:25-145`
- Modify: `endpoint_server/context/projection.py`
- Modify: `endpoint_server/gateway/command_service.py:61-65`
- Modify: `endpoint_server/gateway/ws_routes.py:49-300`
- Test: `tests/context/test_scheduler.py`, `tests/context/test_ingestion.py`, `tests/context/test_diff.py`, `tests/gateway/test_ws_route_asgi.py`

**Interfaces:**
- Produces: `context.inventory.collect`/`context.session.collect`, fixed inventory semantic hash/diff codes, and one active collection per device/profile.
- Consumes: `request_collection_outcome`, ContextCurrent locking and AgentHello capability negotiation.

- [ ] **Step 1: Write failing lifecycle tests.** Assert daily inventory and five-minute session schedule rules. On authenticated AgentHello with inventory capability, assert missing inventory creates one collection; reconnect asserts the count remains one. Assert reordered equivalent inventory has no diff while changed memory, storage, hostname, OS, hardware and adapter data emit their fixed codes.

- [ ] **Step 2: Run targeted lifecycle tests.** Run `python -m pytest tests/context/test_scheduler.py tests/context/test_ingestion.py tests/context/test_diff.py tests/gateway/test_ws_route_asgi.py -q`. Expected: FAIL because profile maps/rules/bootstrap logic are absent.

- [ ] **Step 3: Implement maps and deterministic inventory canonicalization.** Add both profile/capability pairs to ingestion, delivery and WSS allowlists. Add `inventory_v1` 24h and `session_v1` 5m rules. Implement profile-selected canonicalization that excludes collection time, warnings, transient addresses and ordering but includes stable inventory evidence. Add bootstrap after successful auth/Hello/presence using the existing advisory lock and `request_collection_outcome`; request only absent/stale allowed baseline, network and inventory profiles, never session and never unsupported capability.

- [ ] **Step 4: Verify semantic and reconnect behavior.** Run `python -m pytest tests/context/test_scheduler.py tests/context/test_ingestion.py tests/context/test_semantic_hash.py tests/context/test_diff.py tests/gateway/test_ws_route_asgi.py tests/gateway/test_ws_reconnect.py -q`. Expected: PASS.

- [ ] **Step 5: Commit.** Stage only context/gateway implementation and targeted tests, then run `git commit -m "feat(context): schedule inventory lifecycle"`.

### Task 4: Expose strict Inventory and Session SDK support and build the artifact

**Files:**
- Modify: `sdk/python/endpoint_platform_client/_contracts.py`
- Modify: `sdk/python/endpoint_platform_client/models.py:21-151`
- Modify: `sdk/python/endpoint_platform_client/client.py:134-173`
- Modify: `sdk/python/endpoint_platform_client/__init__.py`
- Modify: `sdk/python/pyproject.toml`
- Test: `tests/sdk/test_client.py`
- Create: `tests/sdk/test_inventory_models.py`

**Interfaces:**
- Produces: public `InventoryContext`, `SessionContext`, expanded `SafeContextProfile`, `get_inventory_context()` and `get_session_context()`.
- Consumes: exported endpoint-contract section models and the existing no-redirect `EndpointPlatformClient`.

- [ ] **Step 1: Write failing strict SDK tests.** Parse snapshots for all five safe profiles, assert inventory/session select their exact section model, assert an extra field fails, and assert the two convenience getters issue only GET requests through `get_latest_context`.

- [ ] **Step 2: Run the SDK tests.** Run `python -m pytest tests/sdk/test_client.py tests/sdk/test_inventory_models.py -q`. Expected: FAIL because strict models do not recognize the new profiles or getters.

- [ ] **Step 3: Implement typed SDK surface.** Expand the literal and frozen safe profile set, add the two profile-to-section mappings, public aliases and convenience getters. Preserve `extra=forbid`, CA verify, bearer-from-file, disabled redirects and read-only retry. Bump the SDK project version in `sdk/python/pyproject.toml`.

- [ ] **Step 4: Verify and build.** Run `python -m pytest tests/sdk -q`, then `python -m build sdk/python --wheel --sdist --outdir artifacts/sdk-inventory`. Expected: tests pass and the output has one wheel and one sdist with the bumped version; do not add artifacts to Git.

- [ ] **Step 5: Commit.** Stage only SDK and SDK-test source files, then run `git commit -m "feat(sdk): expose inventory context profiles"`.

### Task 5: Document the delivered boundary and perform release-quality verification

**Files:**
- Modify: `PLANS.md`
- Modify: the existing Device Context boundary document located with `rg -n "Device Context|gateway_wss" docs`
- Test: `tests/contracts`, `tests/context`, `tests/gateway`, `tests/sdk`

**Interfaces:**
- Produces: current documentation of safe service projection, sole WSS path, deferred platform collector tracks and no-production status.
- Consumes: all preceding commits and generated SDK artifact.

- [ ] **Step 1: Document exactly what landed.** State that safe inventory/session profiles cross HTTPS only; Agent traffic remains `/agent/v1/connect`; no raw payload, credentials, PostgreSQL or consumer command scopes are exposed. State Windows/ALT collectors and canary/production rollout remain follow-up plans.

- [ ] **Step 2: Run focused verification.** Run `python -m pytest tests/contracts tests/context tests/gateway tests/sdk -q`, `git diff main...HEAD --check`, and `git status --short`. Expected: suites pass, diff check has no output, and no generated artifact is staged.

- [ ] **Step 3: Inspect change impact and complete diff.** Run GitNexus `detect_changes` against `main`, inspect every affected process, then review `git diff main...HEAD` including public contracts and scopes. Verify dynamic dispatch paths against source/tests.

- [ ] **Step 4: Commit documentation if changed.** Stage exact documentation paths only and run `git commit -m "docs(context): record inventory telemetry boundary"`.

## Plan Self-Review

- **Coverage:** Tasks 1-4 implement server tracks 1-2 from the design: strict additive profiles, corrected last-seen/online, sole-WSS guardrail, lifecycle/bootstrap/semantic changes, safe service exposure and typed SDK artifact.
- **Scope:** ALT and Windows collectors are independent platform acceptance units and require their own follow-up plans; rollout is expressly excluded.
- **Type consistency:** `inventory_v1` and `session_v1` are the same literals in contracts, maps, scheduling, service projection and SDK.
