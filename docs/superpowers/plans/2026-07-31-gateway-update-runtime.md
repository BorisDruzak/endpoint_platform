# Gateway Update Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a TLS-only, Gateway-native ALT agent update and rollback lifecycle, verified on the dedicated test machine before any wider rollout.

**Architecture:** A new small runtime composes the existing strict device-bearer update adapter with ALT-specific local release staging.  The existing Gateway poller remains responsible for context commands; the new runtime owns update recommendation, durable lifecycle acknowledgements and clean handoff to an ALT-aware launcher.  The launcher preserves its immutable bundle layout and exact selection schema.

**Tech Stack:** Python 3.11, aiohttp, Pydantic contracts, PyInstaller ALT bundles, pytest, systemd.

## Global Constraints

- Use only `https://endpoint.sosnadmin.local` with the installed CA and hostname verification.
- The finalized ALT systemd service must never start the legacy Helpdesk WebSocket/API runtime or fallback.
- Controller update journal versions and ALT manifest versions are SemVer; the pilot baseline is reinstalled on `test-agent-lin` before controller-driven update.
- Validate archive hash, size, manifest file hashes/modes and source revision before changing `/opt/endpoint-agent/current.json`.
- Preserve selector keys `schema_version`, `source_revision`, and `version`; do not use the desktop install selector schema for ALT.
- Test the canary and rollback only on `test-agent-lin`; do not update a production endpoint during this phase.
- Update `PLANS.md`, `pc_agent/docs/CODEMAP.md`, and the ALT runbook with each externally visible lifecycle change.

---

## File map

- `pc_agent/endpoint_gateway.py` — shared fixed-origin TLS session and Gateway startup composition.
- `pc_agent/gateway_update_runtime.py` — recommendation polling, durable lifecycle journal, staging and scheduled handoff.
- `pc_agent/alt_update_installer.py` — safe extraction, ALT manifest validation, immutable publish and rollback selection support.
- `pc_agent/launcher/launcher_main.py` — selects ALT installer from an explicit environment flag and records terminal outcomes without leaking data.
- `deploy/agent/alt/endpoint-agent.service` — enables the ALT update mode only for the dedicated systemd service.
- `deploy/agent/alt/install-endpoint-agent.sh` — validates semantic release metadata and preserves the selector contract on first install/finalization.
- `pc_agent/tests/test_gateway_update_runtime.py` and `pc_agent/tests/test_alt_update_installer.py` — deterministic unit tests.
- `pc_agent/tests/test_linux_packaging.py`, `docs/runbooks/ALT_AGENT_INSTALL.md`, `pc_agent/docs/CODEMAP.md`, `PLANS.md` — packaging and operator documentation.

### Task 1: Fixed Gateway update boundary

**Files:**
- Create: `pc_agent/gateway_update_runtime.py`
- Test: `pc_agent/tests/test_gateway_update_runtime.py`

**Interfaces:**
- Consumes: `EndpointUpdateAdapter`, `EndpointRecommendation`, `PERMANENT_CREDENTIAL_PATH` and the fixed Gateway TLS context.
- Produces: `GatewayUpdateRuntime.run_once()` and `GatewayUpdateRuntime.report_startup_outcome()`.

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_gateway_runtime_stages_only_newer_linux_canary_recommendation(tmp_path):
    runtime = GatewayUpdateRuntime(adapter=adapter, data_root=tmp_path, current_version="3.1.76")
    result = await runtime.run_once()
    assert result.status == "scheduled"
    assert (tmp_path / "updates" / "pending_alt_update.json").exists()

@pytest.mark.asyncio
async def test_gateway_runtime_does_not_use_a_legacy_fallback(tmp_path):
    adapter = _AdapterThatReportsUnavailable()
    runtime = GatewayUpdateRuntime(adapter=adapter, data_root=tmp_path, current_version="3.1.76")
    assert (await runtime.run_once()).status == "unavailable"
    assert adapter.legacy_called is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest pc_agent/tests/test_gateway_update_runtime.py -q`

Expected: FAIL because `GatewayUpdateRuntime` does not exist.

- [ ] **Step 3: Implement the minimal runtime**

```python
class GatewayUpdateRuntime:
    async def run_once(self) -> GatewayUpdateRunResult:
        recommendation = await self._adapter.fetch_recommendation(
            platform="linux_amd64", channel="canary"
        )
        if recommendation.recommendation is None:
            return GatewayUpdateRunResult("unavailable" if recommendation.unavailable else "idle")
        if not is_strictly_newer(recommendation.recommendation.version, self._current_version):
            return GatewayUpdateRunResult("idle")
        return await self._stage(recommendation.recommendation)
```

Use a `legacy_fetch=None` adapter, call `acknowledge(operation_id, "requested")` before staging and write a mode-0600 JSON pending file atomically.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `python -m pytest pc_agent/tests/test_gateway_update_runtime.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pc_agent/gateway_update_runtime.py pc_agent/tests/test_gateway_update_runtime.py
git commit -m "feat: add Gateway update runtime boundary"
```

### Task 2: ALT immutable release installer

**Files:**
- Create: `pc_agent/alt_update_installer.py`
- Test: `pc_agent/tests/test_alt_update_installer.py`

**Interfaces:**
- Consumes: `updates/pending_alt_update.json`, downloaded `tar.gz`, `install_root/current.json` and immutable `versions/` bundles.
- Produces: `apply_alt_update(install_root, data_root, pending_path) -> tuple[bool, str]` and a terminal history entry containing `operation_id`.

- [ ] **Step 1: Write the failing tests**

```python
def test_alt_apply_preserves_selector_schema_and_previous_release(tmp_path):
    ok, version = apply_alt_update(install_root, data_root, pending_path)
    assert ok is True
    current = json.loads((install_root / "current.json").read_text())
    assert current == {"schema_version": 1, "source_revision": "abc123", "version": "3.1.77-rc.1"}
    assert (install_root / "versions" / "3.1.76").is_dir()

def test_alt_apply_rejects_manifest_hash_mismatch_without_changing_selector(tmp_path):
    ok, _ = apply_alt_update(install_root, data_root, pending_path)
    assert ok is False
    assert json.loads((install_root / "current.json").read_text())["version"] == "3.1.76"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest pc_agent/tests/test_alt_update_installer.py -q`

Expected: FAIL because `apply_alt_update` does not exist.

- [ ] **Step 3: Implement the minimal installer**

```python
def apply_alt_update(install_root: Path, data_root: Path, pending_path: Path) -> tuple[bool, str]:
    payload = load_strict_pending(pending_path)
    staging = extract_checked_tarball(payload, install_root / "versions" / "_staging")
    manifest = validate_alt_manifest(staging)
    publish_immutable_bundle(staging, install_root / "versions" / manifest.version)
    write_selector_atomically(install_root / "current.json", manifest)
    append_alt_history(data_root, payload, success=True)
    return True, manifest.version
```

The implementation must reject links, traversal, duplicate manifest keys, non-SemVer metadata, hash/mode mismatch, and an existing non-identical version directory.  It must retain both selected and previous release directories.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `python -m pytest pc_agent/tests/test_alt_update_installer.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pc_agent/alt_update_installer.py pc_agent/tests/test_alt_update_installer.py
git commit -m "feat: add immutable ALT update installer"
```

### Task 3: Launcher handoff and terminal reporting

**Files:**
- Modify: `pc_agent/launcher/launcher_main.py`
- Modify: `pc_agent/gateway_update_runtime.py`
- Modify: `pc_agent/endpoint_gateway.py`
- Test: `pc_agent/tests/test_gateway_update_runtime.py`
- Test: `pc_agent/tests/test_self_update_runtime.py`

**Interfaces:**
- Consumes: `ENDPOINT_AGENT_ALT_UPDATE_MODE=1`, `pending_alt_update.json`, `update_history.json`, and `last_failed_launch.json`.
- Produces: a scheduled acknowledgement before process exit and exactly one eventual `applied`, `failed`, or `rolled_back` report per operation.

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_startup_retries_scheduled_ack_before_applied_report(tmp_path):
    runtime = GatewayUpdateRuntime(adapter=adapter, data_root=tmp_path, current_version="3.1.77-rc.1")
    await runtime.report_startup_outcome()
    assert adapter.events == ["scheduled", "applied"]

def test_launcher_uses_alt_installer_only_when_alt_mode_is_explicit(monkeypatch):
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    assert select_update_installer().__name__ == "apply_alt_update"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest pc_agent/tests/test_gateway_update_runtime.py pc_agent/tests/test_self_update_runtime.py -q`

Expected: FAIL because the ALT selector and startup outcome reporter are absent.

- [ ] **Step 3: Implement minimal handoff**

```python
if os.environ.get("ENDPOINT_AGENT_ALT_UPDATE_MODE") == "1":
    apply_pending = apply_alt_update
    pending_path = data_root / "updates" / "pending_alt_update.json"
else:
    apply_pending = apply_update
    pending_path = data_root / "updates" / "pending_update.json"
```

Make `endpoint_gateway.run_gateway_forever` create the runtime, report startup outcome once, and poll update recommendations on a bounded cadence independently of context command delivery.  Preserve the current Gateway 401/403 fail-closed behavior.

- [ ] **Step 4: Run focused tests to verify they pass**

Run: `python -m pytest pc_agent/tests/test_gateway_update_runtime.py pc_agent/tests/test_self_update_runtime.py pc_agent/tests/test_endpoint_gateway.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pc_agent/endpoint_gateway.py pc_agent/gateway_update_runtime.py pc_agent/launcher/launcher_main.py pc_agent/tests
git commit -m "feat: report Gateway update lifecycle"
```

### Task 4: Packaging and operator contract

**Files:**
- Modify: `deploy/agent/alt/endpoint-agent.service`
- Modify: `deploy/agent/alt/install-endpoint-agent.sh`
- Modify: `pc_agent/tests/test_linux_packaging.py`
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`
- Modify: `pc_agent/docs/CODEMAP.md`
- Modify: `PLANS.md`

**Interfaces:**
- Consumes: a verified ALT bundle whose manifest version is SemVer.
- Produces: a finalized systemd service with `ENDPOINT_AGENT_ALT_UPDATE_MODE=1` and operator steps for update plus automatic rollback evidence.

- [ ] **Step 1: Write the failing packaging tests**

```python
def test_alt_unit_enables_explicit_alt_update_mode() -> None:
    text = Path("deploy/agent/alt/endpoint-agent.service").read_text()
    assert "Environment=ENDPOINT_AGENT_ALT_UPDATE_MODE=1" in text

def test_alt_installer_accepts_only_semver_bundle_version() -> None:
    assert "SEMVER" in Path("deploy/agent/alt/install-endpoint-agent.sh").read_text()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest pc_agent/tests/test_linux_packaging.py -q`

Expected: FAIL because the unit does not enable the ALT update mode and the installer accepts non-SemVer release versions.

- [ ] **Step 3: Implement the minimal packaging changes**

```ini
Environment=ENDPOINT_AGENT_ALT_UPDATE_MODE=1
```

Validate bundle `version` with the same SemVer pattern used by update contracts; keep `source_revision` as the immutable source identity.  Add an operator runbook section that requires a reinstallation of the test pilot to `3.1.76` before canary scheduling.

- [ ] **Step 4: Run packaging and documentation checks**

Run: `python -m pytest pc_agent/tests/test_linux_packaging.py -q`

Run: `git diff --check`

Expected: PASS and no whitespace errors.

- [ ] **Step 5: Commit**

```bash
git add deploy/agent/alt pc_agent/tests/test_linux_packaging.py docs/runbooks/ALT_AGENT_INSTALL.md pc_agent/docs/CODEMAP.md PLANS.md
git commit -m "docs: define ALT Gateway update rollout"
```

### Task 5: Local and live canary proof

**Files:**
- Modify: `PLANS.md`
- Test: `pc_agent/tests/test_gateway_update_runtime.py`
- Test: `pc_agent/tests/test_alt_update_installer.py`

**Interfaces:**
- Consumes: merged production controller update routes, a fresh SemVer test-agent bundle, and a published canary artifact.
- Produces: documented test-agent evidence for applied update, Gateway reconnect, repeated baseline, and rollback.

- [ ] **Step 1: Run the local verification suite**

Run: `python -m pytest pc_agent/tests/test_gateway_update_runtime.py pc_agent/tests/test_alt_update_installer.py pc_agent/tests/test_endpoint_gateway.py pc_agent/tests/test_linux_packaging.py pc_agent/tests/test_self_update_runtime.py tests/server/test_update_agent_api.py -q`

Expected: PASS.

- [ ] **Step 2: Build and verify a fresh SemVer ALT baseline**

Run the existing ALT build workflow with version `3.1.76`, inspect `manifest.json`, verify executable file modes and install it only on `test-agent-lin` using the existing CA and completed enrollment identity.

- [ ] **Step 3: Publish and schedule exactly one canary**

Publish a new SemVer canary artifact, record its SHA-256 and size through the controller, and schedule only the dedicated test device.  Verify `requested`, then `scheduled`, then terminal `applied` from durable local history.

- [ ] **Step 4: Prove recovery and rollback**

Request another bounded context collection after the new service reconnects.  Then use a deliberately invalid but correctly-addressed canary artifact only on `test-agent-lin`; verify no selector corruption, automatic rollback to the prior immutable release, and terminal `rolled_back` report.

- [ ] **Step 5: Record the verified result and commit**

Update `PLANS.md` with release versions, evidence sources, and residual risks.  Do not include credentials, raw tokens, or raw payloads.

```bash
git add PLANS.md
git commit -m "docs: record Gateway update canary result"
```

## Self-review

- Spec coverage: Tasks 1 and 3 implement strict Gateway lifecycle; Task 2 resolves the discovered ALT selector and immutable-bundle incompatibility; Task 4 enforces SemVer packaging and documents the service switch; Task 5 provides the required canary, reconnect and rollback proof.
- Completeness scan: every task defines concrete files, interfaces, tests, commands, and expected outcomes.
- Type consistency: Task 1 produces `GatewayUpdateRuntime`; Task 2 produces `apply_alt_update`; Task 3 composes exactly those interfaces; Task 4 enables their explicit runtime flag; Task 5 uses the verified release artifacts.

### Task 6: Privileged ALT publication worker

**Files:**
- Create: `deploy/agent/alt/endpoint-agent-update.service`
- Create: `deploy/agent/alt/endpoint-agent-update.path`
- Create: `deploy/agent/alt/apply-pending-alt-update.sh`
- Modify: `pc_agent/launcher/launcher_main.py`
- Modify: `deploy/agent/alt/install-endpoint-agent.sh`
- Modify: `pc_agent/tests/test_alt_launcher_runtime.py`
- Modify: `tests/deploy/test_alt_agent_package.py`
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`
- Modify: `PLANS.md`

**Interfaces:**
- Consumes: `/var/lib/endpoint-agent/updates/pending_alt_update.json`, immutable `/opt/endpoint-agent`, and `apply_alt_update(install_root, data_root, pending_path)`.
- Produces: `--apply-alt-update` launcher mode plus a root-only systemd path/service pair that publishes a verified release and returns the running agent to its dedicated user.

- [ ] **Step 1: Write failing delegation and package tests**

```python
def test_alt_agent_defers_pending_publish_to_privileged_worker(...) -> None:
    assert launcher_main.pending_update_requires_privileged_worker(...) is True

def test_update_worker_is_root_owned_and_restarts_agent_after_apply(...) -> None:
    assert "User=root" in update_service
    assert "systemctl start endpoint-agent.service" in worker_script
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `python -m pytest pc_agent/tests/test_alt_launcher_runtime.py tests/deploy/test_alt_agent_package.py -q`

Expected: FAIL because no worker mode or root-owned units exist.

- [ ] **Step 3: Implement the fixed privilege boundary**

Add `--apply-alt-update` to the stable launcher.  It runs only in ALT mode,
applies one pending file, records its durable result, and exits without
starting the agent.  Normal ALT launchers must exit successfully when a
pending file exists or the agent returns exit `42`; systemd owns the follow-up.

Install a root-owned `endpoint-agent-update.path` that watches the fixed
pending path.  Its service runs a root-owned fixed-path helper which stops the
agent, invokes the stable launcher in worker mode, and attempts to start the
unprivileged agent even if the handled apply fails.  The installer stages,
validates, installs, daemon-reloads, and enables the path unit together with
the main service.  It never grants the `endpoint-agent` user write permission
to `/opt/endpoint-agent`.

- [ ] **Step 4: Run focused tests and package verification**

Run: `python -m pytest pc_agent/tests/test_alt_launcher_runtime.py tests/deploy/test_alt_agent_package.py pc_agent/tests/test_alt_update_installer.py -q`

Run: `bash -n deploy/agent/alt/install-endpoint-agent.sh deploy/agent/alt/apply-pending-alt-update.sh`

Expected: PASS.

- [ ] **Step 5: Rebuild the semantic test baseline and repeat one canary**

Install a verified new baseline only on `test-agent-lin` so its stable launcher
contains worker mode and its installer has enabled the path unit.  Schedule a
fresh `3.1.79` canary only for the dedicated test device.  Verify root worker
application, unprivileged Gateway reconnect, durable `applied`, and a bounded
context collection.  Record a failed pre-worker canary separately as safe
failure evidence, not as a successful update.
