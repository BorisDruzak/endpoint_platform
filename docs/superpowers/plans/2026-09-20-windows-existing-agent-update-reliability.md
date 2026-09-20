# Windows Existing-Agent Update Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make existing Windows-agent upgrades reliable, attestable, bounded, and repeatable.

**Architecture:** Setup compares public release and protected installed versions before MSI invocation. The unprivileged runtime retries only the fixed updater service; the LocalSystem updater validates a signed-by-control-plane, immutable ZIP manifest and writes a provenance selector. The server completes a rollout when its final target becomes terminal.

**Tech Stack:** Python 3.14, PowerShell/WiX, pytest, FastAPI, SQLAlchemy, Windows SCM.

**Spec:** `docs/superpowers/specs/2026-09-20-windows-existing-agent-update-reliability-design.md`

## Global Constraints

- Preserve existing device credentials and enrollment identity during an MSI upgrade.
- Keep updater networking disabled and use the existing CA-verified agent transport.
- Do not write claims, credentials, tokens, or private certificate material to artifacts or logs.
- Test each production behavior RED then GREEN before implementation.
- A live canary happens only after source tests, build verification, and hash/signature verification.

## Review Focus

- An equal or lower Setup version must never downgrade a healthy agent.
- Invalid pending input must not permanently suppress future recommendations.
- The runtime executable version and bundled manifest must match the controller recommendation.
- Archive metadata must not permit disk exhaustion or path escape.
- A terminal target must not leave a rollout displayed as active.

---

### Task 1: Existing Setup upgrade path

**Files:**
- Modify: `pc_agent/platform/windows/setup_entry.py`
- Modify: `pc_agent/tests/windows/test_setup_entry.py`

**Interfaces:**
- `main()` returns `UPDATED`/zero only after a newer embedded MSI has completed and `EndpointAgent` is running.
- Equal and older public installer versions retain `ALREADY_INSTALLED`/10.

- [ ] Write a failing test for newer valid installation upgrade and a failing test for equal-version no-op.
- [ ] Run the focused tests and observe the newer case return `ALREADY_INSTALLED` before the implementation.
- [ ] Add strict semantic-version comparison and the identity-preserving MSI upgrade branch.
- [ ] Run focused Setup tests and commit the atomic change.

### Task 2: Retryable and quarantined pending handoffs

**Files:**
- Modify: `pc_agent/runtime/application.py`
- Modify: `pc_agent/platform/windows/service_control.py`
- Modify: `pc_agent/platform/windows/updater_service.py`
- Modify: `pc_agent/tests/runtime/test_current_update_characterization.py`
- Modify: `pc_agent/tests/windows/test_updater_service.py`

**Interfaces:**
- A `pending` poll asks only `EndpointAgentUpdater` to start and does not terminate the running agent when SCM start fails.
- An invalid pending file moves out of the fixed active filename before the updater exits rejected.

- [ ] Write failing retry and quarantine behavior tests.
- [ ] Run them to observe the pending state remains blocking.
- [ ] Implement minimal idempotent SCM start handling and protected quarantine.
- [ ] Run focused tests and commit.

### Task 3: Attested, bounded Windows update bundle

**Files:**
- Modify: `pc_agent/platform/windows/updater_service.py`
- Modify: `pc_agent/platform/windows/startup_confirmation.py`
- Modify: `packaging/windows/build-update-zip.ps1`
- Modify: `pc_agent/tests/windows/test_updater_service.py`
- Modify: `pc_agent/tests/windows/test_windows_update_rollback.py`

**Interfaces:**
- `endpoint-update-manifest.json` supplies version/source revision/file hashes for the staged runtime.
- `WindowsUpdater` publishes only an attested candidate and writes a schema-1 selector.

- [ ] Write failing tests for mismatched executable version, bad package manifest, archive-member count, and extracted-size limits.
- [ ] Run them to observe current acceptance/unbounded extraction.
- [ ] Add manifest validation, executable-version validation, extraction limits, and provenance selector writes.
- [ ] Add the deterministic ZIP build script and run focused tests/build checks; commit.

### Task 4: Terminal rollout completion and timeout

**Files:**
- Modify: `endpoint_server/updates/service.py`
- Modify: `tests/server/test_update_service.py`
- Modify: `pc_agent/platform/windows/updater_service.py`
- Modify: `pc_agent/tests/windows/test_windows_update_rollback.py`

**Interfaces:**
- `record_report()` completes an active or paused rollout exactly when every target is terminal.
- Candidate startup proof waits up to 600 seconds before a safe rollback.

- [ ] Write failing lifecycle completion and extended-window behavior tests.
- [ ] Run them to observe the rollout remains active/current window is shorter.
- [ ] Implement atomic completion/audit and bounded timeout change.
- [ ] Run server and Windows focused suites; commit.

### Task 5: Release, live existing-agent canary, and repeat update

**Files:**
- Modify: `packaging/windows/README.md`
- Modify: `docs/superpowers/specs/2026-09-19-universal-windows-enrollment-installer-design.md`

- [ ] Build and validate a signed Setup/MSI release containing Task 1.
- [ ] Use it to upgrade the existing dedicated Windows test agent while preserving its enrollment identity.
- [ ] Build/register a newer authenticated Windows ZIP, create a one-device canary, and verify the online update from WSS handshake through terminal report.
- [ ] Create one further newer ZIP canary, verify the second consecutive update and no-op repeat recommendation.
- [ ] Verify services, selector provenance, canary status, server targets/rollouts, hashes, signatures, and full source suite; commit documentation.

## Self-review

- Tasks 1 and 2 establish safe entry/retry behavior before Task 3 changes the package format.
- Task 3 produces provenance consumed by Task 5.
- Task 4 changes only update-target lifecycle and has server transaction coverage.
- Live operations are isolated to the dedicated Windows test agent and a one-device canary after source-level gates.
