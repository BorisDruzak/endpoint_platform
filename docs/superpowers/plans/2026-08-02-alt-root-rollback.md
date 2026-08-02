# ALT Root-Mediated Crash Rollback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move ALT crash rollback from the unprivileged launcher to the existing fixed root worker while preserving strict selector ownership and repairing replaced claim-free units idempotently.

**Architecture:** A successful privileged ALT update records the fully verified current selector in root-owned `previous.json`. The service launcher can only emit a strict fixed rollback request; the existing root worker validates that request against both root-owned selectors and the previous immutable release before atomically replacing `current.json`. The installer finalizer always applies one fixed post-enrollment unit transformation after validating durable identity.

**Tech Stack:** Python 3, pytest, Bash, systemd unit files, atomic JSON file replacement.

## Global Constraints

- No production or test-agent mutation/canary.
- Keep `/opt/endpoint-agent`, its selectors, and the stable launcher root-owned.
- Keep `endpoint-agent.service` unprivileged with `ProtectSystem=strict`.
- No request field or worker argument may select a filesystem path or command.
- Service-writable history is diagnostics, never rollback authority.
- Legacy non-ALT rollback behavior must remain unchanged.

---

### Task 1: Production-like regression and root selector authority

**Files:**
- Modify: `pc_agent/tests/test_alt_launcher_runtime.py`
- Modify: `pc_agent/tests/test_alt_update_installer.py`
- Modify: `pc_agent/alt_update_installer.py`

**Interfaces:**
- Produces: `write_alt_rollback_request(install_root: Path, data_root: Path, crashed_version: str) -> Path`.
- Produces: `apply_alt_rollback(install_root: Path, data_root: Path) -> tuple[bool, str]`.
- Produces: root-owned strict selector authority at `<install_root>/previous.json`.

- [ ] **Step 1: Write RED tests**

Add a crash test that makes writes to `current.json` raise `PermissionError`,
allows writes under `data/updates`, and asserts the ALT launcher leaves the
selector unchanged while creating only canonical `rollback-request.json`.

Add update-installer tests with complete legacy/headless manifests asserting:

```python
assert load_json(install_root / "previous.json") == {
    "schema_version": 1,
    "source_revision": "accepted-revision",
    "version": "3.1.90",
}
```

and asserting a successful root rollback selects that exact verified release,
removes the request, and creates a final `startup_crash_rollback` marker.

- [ ] **Step 2: Verify RED**

Run:

```text
python -m pytest pc_agent/tests/test_alt_launcher_runtime.py pc_agent/tests/test_alt_update_installer.py -q
```

Expected: failures for missing request writer, missing `previous.json`, missing
root rollback worker, and the existing attempted selector write.

- [ ] **Step 3: Implement strict authority and request protocol**

In `pc_agent/alt_update_installer.py`, keep the selector schema exact and add:

```python
ROLLBACK_REQUEST_SCHEMA = "endpoint_alt_rollback_request_v1"
ROLLBACK_REQUEST_NAME = "rollback-request.json"
PREVIOUS_SELECTOR_NAME = "previous.json"

def write_alt_rollback_request(
    install_root: Path, data_root: Path, crashed_version: str
) -> Path: ...

def apply_alt_rollback(
    install_root: Path, data_root: Path
) -> tuple[bool, str]: ...
```

The update path must verify the selected release, atomically write its selector
to `previous.json`, then publish the new current selector. The rollback worker
must use only the fixed request name, compare exact current/previous identities,
verify the previous manifest/tree, atomically write `current.json`, emit the
terminal marker only afterward, and archive rejected requests to one fixed
failure filename.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 command and require all tests to pass.

### Task 2: Launcher crash handoff and legacy safety

**Files:**
- Modify: `pc_agent/launcher/launcher_main.py`
- Modify: `pc_agent/tests/test_launcher_main.py`
- Modify: `pc_agent/tests/test_alt_launcher_runtime.py`

**Interfaces:**
- Consumes: `write_alt_rollback_request(...)` and `apply_alt_rollback(...)`.
- Produces: root-only CLI mode `--apply-alt-rollback` with no selector/path target argument.

- [ ] **Step 1: Write RED tests**

Test three bad headless launches followed by clean launcher exit, unchanged
`current.json`, exact request contents, and no launch of the prior release before
the root worker acts. Add root-mode tests for ALT-only/root-only enforcement and
mutual exclusion with update-worker mode. Retain the existing legacy four-launch
test and exact legacy selector result.

- [ ] **Step 2: Verify RED**

Run:

```text
python -m pytest pc_agent/tests/test_launcher_main.py pc_agent/tests/test_alt_launcher_runtime.py -q
```

Expected: ALT test fails because the launcher still writes the selector directly.

- [ ] **Step 3: Implement minimal launcher handoff**

Add `--apply-alt-rollback`. In ALT crash handling, write
`startup_crash_rollback_requested`, create the fixed request, and exit without
touching `/opt`. In privileged mode, require ALT mode and root, call
`apply_alt_rollback`, log a sanitized result, and return control to systemd.
Keep `_rollback_current_version()` only on the non-ALT branch.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 command and require all tests to pass.

### Task 3: Existing fixed root worker integration

**Files:**
- Modify: `deploy/agent/alt/apply-pending-alt-update.sh`
- Modify: `deploy/agent/alt/endpoint-agent-update.path`
- Modify: `deploy/agent/alt/endpoint-agent-update.service`
- Modify: `deploy/agent/alt/install-endpoint-agent.sh`
- Modify: `tests/deploy/test_alt_agent_package.py`

**Interfaces:**
- Consumes: fixed request `/var/lib/endpoint-agent/updates/rollback-request.json`.
- Produces: stable-launcher invocation `--apply-alt-rollback` without caller input.

- [ ] **Step 1: Write RED deployment behavior tests**

Assert the path unit watches both fixed request files, the service no longer has
a pending-update-only condition, the helper validates rollback request owner,
group, exact `0600` mode, regular-file and non-symlink status, prioritizes
rollback, and calls only the stable launcher with fixed roots. Assert existing
`ReadWritePaths`, service user, and `ProtectSystem` values are unchanged.

- [ ] **Step 2: Verify RED**

Run:

```text
python -m pytest tests/deploy/test_alt_agent_package.py -q
```

Expected: failures for the absent rollback watch, validation, and invocation.

- [ ] **Step 3: Implement fixed helper behavior**

Extend the existing helper; do not add a privileged unit. Validate the fixed
request metadata before stopping the agent. If present, invoke
`$STABLE_LAUNCHER --apply-alt-rollback --no-gui --data-dir $DATA_ROOT
--install-root $INSTALL_ROOT`; otherwise retain fixed update mode. Return only
the known diagnostic files to the service account.

- [ ] **Step 4: Verify GREEN and shell syntax**

Run:

```text
python -m pytest tests/deploy/test_alt_agent_package.py -q
bash -n deploy/agent/alt/apply-pending-alt-update.sh
bash -n deploy/agent/alt/install-endpoint-agent.sh
```

### Task 4: Idempotent claim-free installed-unit migration

**Files:**
- Modify: `deploy/agent/alt/install-endpoint-agent.sh`
- Modify: `tests/deploy/test_alt_agent_finalizer_protocol.py`

**Interfaces:**
- Produces: `finalize_service_unit()` operating only on the fixed installed unit.

- [ ] **Step 1: Write RED finalizer harness cases**

After claim and request removal, replace the fixture unit with the bootstrap
unit, invoke `--finalize-handoff`, and assert claim `LoadCredential` and handoff
environment are absent, gateway-ready is present, and exit is zero. Invoke a
second time and require the same result. Remove enrollment identity or permanent
credential in separate cases and require failure with the unit unchanged.

- [ ] **Step 2: Verify RED**

Run:

```text
python -m pytest tests/deploy/test_alt_agent_finalizer_protocol.py -q
```

Expected: replaced-unit/idempotency assertions fail because the existing early
return skips unit migration.

- [ ] **Step 3: Implement the fixed idempotent transformation**

Extract the current three fixed `sed` edits plus `daemon-reload` into
`finalize_service_unit()`. In the no-request/no-claim branch, validate the
permanent credential and enrollment identity, invoke that function, and return
success. Keep all current request/claim path, owner, mode, digest, and identity
checks for first finalization.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 command and require all tests to pass.

### Task 5: Documentation, broad verification, and commit

**Files:**
- Modify: `docs/runbooks/ALT_AGENT_INSTALL.md`
- Modify: `pc_agent/docs/AGENT_UPDATE_WORKFLOW.md`
- Modify: `pc_agent/docs/SELF_UPDATE.md`
- Modify: `pc_agent/docs/CODEMAP.md`
- Modify: `docs/agent/CURRENT_ALT_RUNTIME_BASELINE.md`
- Modify: `.superpowers/sdd/04-alt-rpm/task-9-report.md` (ignored report)

**Interfaces:**
- Documents: fixed request, root authority, failure behavior, legacy boundary, and claim-free migration.

- [ ] **Step 1: Update docs and report**

Document that `previous.json` is root authority, the request carries identities
only, the existing worker re-verifies the immutable release, final rollback
reporting occurs only after selector publication, and a replaced finalized unit
must be repaired through idempotent finalization. Append RED/GREEN evidence and
confirm no remote mutation.

- [ ] **Step 2: Run focused verification**

```text
python -m pytest pc_agent/tests/test_alt_update_installer.py pc_agent/tests/test_alt_launcher_runtime.py pc_agent/tests/test_launcher_main.py pc_agent/tests/test_gateway_update_runtime.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py -q
```

- [ ] **Step 3: Run repository verification**

```text
python scripts/verify_workspace.py
python -m pytest tests/build/test_linux_headless_artifact.py tests/deploy pc_agent/tests/test_launcher_main.py pc_agent/tests/test_alt_launcher_runtime.py pc_agent/tests/test_alt_update_installer.py pc_agent/tests/test_gateway_update_runtime.py pc_agent/tests/test_self_update_runtime.py pc_agent/tests/runtime pc_agent/tests/transport -q
python -m ruff check pc_agent/alt_update_installer.py pc_agent/launcher/launcher_main.py pc_agent/tests/test_alt_update_installer.py pc_agent/tests/test_alt_launcher_runtime.py pc_agent/tests/test_launcher_main.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py
python -m ruff format --check pc_agent/alt_update_installer.py pc_agent/launcher/launcher_main.py pc_agent/tests/test_alt_update_installer.py pc_agent/tests/test_alt_launcher_runtime.py pc_agent/tests/test_launcher_main.py tests/deploy/test_alt_agent_package.py tests/deploy/test_alt_agent_finalizer_protocol.py
git diff --check
```

- [ ] **Step 4: Inspect and commit**

Review `git diff --stat`, `git diff`, and `git status --short`. Commit code, tests,
and synchronized docs with:

```text
git commit -m "pc_agent: mediate ALT crash rollback through root worker"
```

Do not amend the prior sanitized canary evidence commit and do not perform a
remote deployment or canary.
