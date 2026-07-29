# Agent Update Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.

**Goal:** Let `pc_agent` consume Endpoint Platform update recommendations and report lifecycle outcomes while preserving launcher self-update semantics.

**Architecture:** Add `pc_agent/update_adapter.py`, a narrow adapter that maps strict `/agent/v1/updates` contracts to the existing update command/pending-file path. `WSAgent` remains the owner of the existing command, pending file, shutdown and exit-42 behavior. New API is primary; legacy HTTP is fallback only for explicit unavailable transport. Launcher remains untouched.

**Tech Stack:** Python asyncio/aiohttp, existing `WSAgent`, orchestrator update command, pytest.

## Global Constraints

- Do not change launcher apply/verify/rollback logic, update exit code, artifact build/upload, UI, WebSocket, production or bulk rollout.
- Preserve pending-update idempotency and never log bearer values, raw URLs with credentials, paths, traces or logs.
- New endpoint valid no-assignment is final; legacy fallback occurs only for 404/501/connection unavailable.
- Report `requested`, `scheduled`, `applied`, `failed` or `rolled_back` with durable idempotency keys and safe codes only.
- Primary GET is `/agent/v1/updates/recommendation?platform={windows_amd64|linux_amd64}&channel={stable|canary}`. A strict 200 body is an `AgentUpdateRecommendationV1`; 204 is a final no-assignment.
- Strict parsing verifies schema version, lowercase UUID operation id, SemVer, platform/channel, canonical HTTPS URL with no credentials/query/fragment, archive/name pair, SHA-256 and positive size. A malformed body is fail-closed and creates no pending update.
- Legacy GET is allowed only after 404, 501, `aiohttp.ClientConnectionError` or `asyncio.TimeoutError`. It is forbidden after 200, 204, authentication/authorization errors, conflict, validation error, malformed JSON or any other HTTP status.
- The terminal-report journal is `<data_root>/updates/endpoint_update_reports.json`; its records contain only `operation_id`, `report_key`, `status`, `reported_version`, `safe_code`, and `delivered_at`. Write through a temporary sibling then `Path.replace()`.

## File Structure

- `pc_agent/update_adapter.py` owns typed primary requests, exact fallback classification, lifecycle requests and the atomic terminal-report journal.
- `pc_agent/ws_agent.py` constructs the adapter, maps a recommendation to the existing update command and observes local post-restart state.
- `pc_agent/tests/test_update_adapter.py` covers transport, strict parsing, fallback and report-key durability.
- `pc_agent/tests/test_self_update_runtime.py` covers WSAgent handoff while retaining current pending/scheduling behavior.

### Task 1: Strict client transport and recommendation mapping

**Files:**
- Create: `pc_agent/update_adapter.py`
- Modify: `pc_agent/ws_agent.py`
- Test: `pc_agent/tests/test_update_adapter.py`

**Interfaces:**

- `EndpointRecommendation(operation_id, version, platform, channel, artifact_url, artifact_name, archive_type, sha256, size, reason)` is a frozen normalized value.
- `RecommendationResult(source, recommendation, unavailable, safe_error)` exposes a strict primary result or the explicitly eligible legacy result.
- `EndpointUpdateAdapter.fetch_recommendation(*, platform, channel)` issues the primary request using only the current bearer header.

- [ ] Write RED tests with one valid primary 200 fixture and one 204 fixture. Assert that 204 returns `source == "endpoint"`, no recommendation and never invokes the injected legacy coroutine. Add malformed URL/schema fixtures and assert `safe_error == "endpoint_contract_invalid"` with no pending file.
- [ ] Run `python -m pytest pc_agent/tests/test_update_adapter.py -q` and verify collection fails before `pc_agent.update_adapter` exists.
- [ ] Implement `EndpointUpdateAdapter.fetch_recommendation()`: parse only `AgentUpdateRecommendationV1` fields, reject unknown/malformed data, map to the frozen normalized value, and discard response text on failure. Validate URLs with `urlsplit()` and do not log their value.
- [ ] Run `python -m pytest pc_agent/tests/test_update_adapter.py -q; python -m ruff format --check pc_agent/update_adapter.py pc_agent/tests/test_update_adapter.py`; commit `feat: add endpoint update adapter`.

### Task 2: Acknowledgement/report lifecycle and durable idempotency

**Files:**
- Modify: `pc_agent/update_adapter.py`
- Modify: `pc_agent/ws_agent.py`
- Test: `pc_agent/tests/test_update_adapter.py`
- Test: `pc_agent/tests/test_self_update_runtime.py`

**Interfaces:**

- `acknowledge(operation_id, status)` accepts exactly `requested` and `scheduled`; only HTTP 204 succeeds.
- `report_terminal(operation_id, *, status, reported_version, safe_code)` accepts exactly `applied`, `failed`, `rolled_back`; only HTTP 200 succeeds.
- `WSAgent._legacy_fetch_update_status()` contains the current legacy GET behavior. `WSAgent._fetch_update_status()` asks the adapter first and passes the legacy coroutine only on an eligible failure.

- [ ] Write RED tests: primary 404/501 and connection failure call legacy once; 401/403/409/422/500 never do. Assert endpoint 200 produces `recommended_build` with target/channel/version/artifact fields but no artifact URL in status/action-trace details. Assert `requested` precedes existing scheduling and `scheduled` follows its success.
- [ ] Write a restart test: a failed terminal POST reuses the same generated opaque report key on a new adapter instance. Its body must contain neither a path, URL, exception, trace nor raw history object.
- [ ] Implement bounded fallback. Preserve existing legacy POST behavior only for legacy recommendations; a primary recommendation must use the existing verified local scheduling path. Implement journaled reports and map observations only to `launcher_apply_failed`, `launcher_rolled_back`, and `post_restart_handshake_confirmed`.
- [ ] Run `python -m pytest pc_agent/tests/test_update_adapter.py pc_agent/tests/test_self_update_runtime.py -q`; commit `feat: report endpoint update lifecycle`.

### Task 3: Compatibility, docs and local canary gate

**Files:**
- Modify: `pc_agent/docs/SELF_UPDATE.md`
- Modify: `pc_agent/docs/AGENT_UPDATE_WORKFLOW.md`
- Modify: `pc_agent/docs/CODEMAP.md`
- Test: `pc_agent/tests/test_self_update_runtime.py`

- [ ] Add regression matrix: primary 200 assignment/no legacy; primary 204/no assignment/no legacy; 404/501/connection/timeout legacy once; 401/403/409/422/malformed/other fail closed; pending skip; rollback as older normal assignment.
- [ ] Update docs with the endpoint contract, fallback boundary, report-key privacy, release/canary prerequisites and explicit statement that `scheduled` is launcher handoff whereas `applied` needs a post-restart handshake.
- [ ] Run `python -m pytest pc_agent/tests -q; python -m pytest tests -q; python scripts/generate_contract_artifacts.py --check; python -m ruff format --check pc_agent/update_adapter.py pc_agent/ws_agent.py pc_agent/tests/test_update_adapter.py pc_agent/tests/test_self_update_runtime.py`. Do not run a canary in this task; record that it requires a separately authorized verified artifact upload, one assigned test device, launcher diagnostics and a post-restart endpoint handshake.
- [ ] Run `git diff --check` and secrecy check `rg -n -i "authorization.*(log|detail)|artifact_url.*(log|detail)|pending.*(log|detail)" pc_agent/update_adapter.py pc_agent/ws_agent.py`; commit docs if changed.

### Task 4: Acceptance

- [ ] Run full repository tests, strict contracts/artifacts, update adapter suite and no-secret grep/diff checks.
- [ ] Build no release artifact and do not contact remote hosts unless separately authorized.  Record what must precede a real test-agent canary: build upload, rollout assignment, launcher diagnostics and post-restart handshake.
