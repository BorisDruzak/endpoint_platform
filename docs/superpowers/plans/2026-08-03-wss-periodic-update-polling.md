# Periodic WSS Update Polling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver rollout recommendations created after a healthy WSS connection without restarting the agent.

**Architecture:** The lifecycle owns background tasks for one connected Gateway session and cancels them before closing that session.  The headless application supplies one WSS-only task that performs the existing TLS-authenticated update-recommendation flow immediately and then every five minutes.  The task never calls the HTTP command receive method and an update handoff still exits with code 42 through the lifecycle.

**Tech Stack:** Python 3.12, asyncio, aiohttp, pytest.

## Global Constraints

- Gateway commands remain WSS-only when `migration_http_pull_fallback=false`.
- HTTPS remains the bounded transport for update recommendation and artifacts.
- A periodic task is scoped to one WSS connection and is cancelled before reconnect.
- Existing update integrity, ALT root-worker handoff, and exit-code semantics remain unchanged.
- No credentials, device identifiers, CA paths, or raw payloads enter tests or documentation.

---

### Task 1: Connection-scoped background-task lifecycle

**Files:**
- Modify: `pc_agent/runtime/lifecycle.py`
- Modify: `pc_agent/tests/runtime/test_headless_lifecycle.py`

**Interfaces:**
- `RuntimeDependencies.create_connected_tasks(settings, credential, transport)` returns an iterable of awaitables.
- `_run_connected(..., connected_tasks=...)` starts those awaitables with receive and heartbeat loops and cancels all of them when any loop completes.

- [x] **Step 1: Write the failing lifecycle cancellation test**

Add a dependency factory that returns a task blocked on an `asyncio.Event`; record its `finally` clause.  Use a transport whose receive loop exits and assert the runtime cancels the task before transport/executor cleanup.

- [x] **Step 2: Run the focused test to verify RED**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py::test_runtime_cancels_connected_background_tasks_before_transport_cleanup -q`

Expected: FAIL because `RuntimeDependencies` has no connected-task factory and `_run_connected` does not own that task.

- [x] **Step 3: Implement the minimal lifecycle contract**

Add a default empty connected-task factory to `RuntimeDependencies`.  Construct its awaitables only after a successful Gateway hello, pass their asyncio tasks into `_run_connected`, and cancel/await them in the existing `finally` block with receive and heartbeat tasks.

- [x] **Step 4: Run the focused lifecycle test to verify GREEN**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py::test_runtime_cancels_connected_background_tasks_before_transport_cleanup -q`

Expected: PASS.

### Task 2: Periodic WSS update recommendation loop

**Files:**
- Modify: `pc_agent/runtime/application.py`
- Modify: `pc_agent/version.py`
- Modify: `pc_agent/tests/transport/test_websocket_reconnect.py`
- Modify: `pc_agent/docs/AGENT_UPDATE_WORKFLOW.md`

**Interfaces:**
- `_periodic_https_update_checks(settings, credential, state, sleep=...)` performs the existing HTTPS update check immediately, then sleeps `GATEWAY_UPDATE_POLL_INTERVAL_SEC` between later checks.
- `_default_dependencies()` supplies that task only when `RuntimeSettings.transport_mode == "gateway_wss"`.

- [x] **Step 1: Write the failing periodic-poll test**

Replace the single WSS connection-hook assertion with a test that injects an update-only HTTP transport and a cancelling sleep coroutine.  Assert one recommendation connection and close occur before the first sleep, the sleep is exactly `GATEWAY_UPDATE_POLL_INTERVAL_SEC`, and no HTTP `receive` method is called.

- [x] **Step 2: Run the focused test to verify RED**

Run: `python -m pytest pc_agent/tests/transport/test_websocket_reconnect.py::test_runtime_wss_periodically_checks_updates_without_http_command_receive -q`

Expected: FAIL because the application exposes only the connection callback and has no periodic task.

- [x] **Step 3: Implement the minimal WSS-only task**

Move the existing `_https_update_hook` work into `_periodic_https_update_checks`.  Reuse `_create_http_pull_transport(...).connect(compatibility_agent_hello())` and `.close()` for each check, preserving the existing update runtime and its `SystemExit(EXIT_UPDATE_PENDING)`.  Register the task through `create_connected_tasks`; do not pass an update callback to `WebSocketGatewayTransport`.

- [x] **Step 4: Document the timing and transport boundary**

State that WSS commands do not fall back to HTTP, while update recommendations and artifacts use authenticated HTTPS after a WSS session is established and repeat every five minutes for that session.

- [x] **Step 5: Advance the immutable agent version**

Set `AGENT_VERSION` from `3.1.89` to `3.1.91`.  The pre-registered `3.1.90` artifact remains the isolated intentional-failure canary and is never replaced.

- [x] **Step 6: Run focused checks and commit**

Run:

```powershell
python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/transport/test_websocket_reconnect.py -q
python -m pytest pc_agent/tests/test_self_update_runtime.py pc_agent/tests/test_alt_update_installer.py -q
git diff --check
```

Commit:

```powershell
git add pc_agent/runtime/lifecycle.py pc_agent/runtime/application.py pc_agent/version.py pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/transport/test_websocket_reconnect.py pc_agent/docs/AGENT_UPDATE_WORKFLOW.md
git commit -m "pc_agent: poll updates during WSS sessions"
```

### Task 3: Approved Windows initial-runtime transition

**Files:**
- Create: `packaging/windows/initial-runtime-3.1.91.json`
- Modify: `tests/packaging/test_initial_runtime_contract.py`

**Interfaces:**
- The checked-in manifest version, agent version, staged artifact identity, source hashes, producer identity, and a new canonical component GUID form one approved immutable Windows runtime transition.

- [x] **Step 1: Build the Windows headless runtime with deterministic inputs**

Run PyInstaller with `PYTHONHASHSEED=0` and the existing Windows headless spec into a new dedicated temporary directory.  Inspect its artifact identity through `initial_runtime_contract.py --print-artifact`.

- [x] **Step 2: Write the new immutable manifest and update the current-product test**

Create `initial-runtime-3.1.91.json` with the observed artifact identity, the actual CPython/PyInstaller producer identity, fresh uppercase GUID, and hashes for the fixed manifest source list.  Point the current-product test at 3.1.91.

- [x] **Step 3: Verify the approved transition**

Run:

```powershell
python -m pytest tests/packaging/test_initial_runtime_contract.py -q
python packaging/windows/initial_runtime_contract.py --repository-root . --manifest packaging/windows/initial-runtime-3.1.91.json --baseline packaging/windows/initial-runtime.json --approve-version --approve-source
```

Expected: the manifest validates as an approved transition and its version equals `AGENT_VERSION`.

## Self-review

- The plan covers the accepted design: immediate check, five-minute checks, lifecycle cancellation, and no command receive call.
- Task 1 establishes the lifecycle contract before Task 2 consumes it.
- All referenced functions and files exist or are defined by the prior task.
- The focused checks cover the updated runtime, update handoff, ALT rollback path, and the required Windows immutable-runtime transition.
