# Endpoint Agent V2 Implementation Plan — 01 Architecture And Baseline

## Task 0: Record the exact baseline and architecture decisions

**Files:**
- Create: `docs/adr/0001-endpoint-platform-boundary.md`
- Create: `docs/adr/0002-neutral-agent-transport.md`
- Create: `docs/adr/0003-native-agent-packaging.md`
- Create: `tests/architecture/test_endpoint_platform_boundaries.py`
- Modify: `PLANS.md`

**Interfaces:**
- Produces the non-negotiable ownership and transport rules used by all later tasks.

- [ ] **Step 1: Create an isolated worktree**

PowerShell:

```powershell
git fetch origin
git worktree add ..\endpoint-platform-agent-runtime -b codex/headless-agent-runtime origin/main
Set-Location ..\endpoint-platform-agent-runtime
git rev-parse HEAD
git status --short
```

Expected: exact starting SHA printed and clean worktree.

- [ ] **Step 2: Write failing architecture tests**

The test scans `endpoint_server` and fails if a generic relay route or generic outbound URL execution is introduced:

```python
FORBIDDEN_ROUTE_FRAGMENTS = {
    "/proxy",
    "/relay",
    "/invoke-service",
    "/forward",
}

FORBIDDEN_RUNTIME_IMPORTS = {
    "pc_agent.ui_gui",
    "pc_agent.ui_bridge",
    "pc_agent.ui_gui.server_api",
}
```

It also asserts that the future `pc_agent/runtime` package contains no forbidden imports.

Initially the runtime-package assertion fails because the package does not exist.

- [ ] **Step 3: Write ADR 0001**

Required decision:

```text
Endpoint Platform is the exclusive endpoint-agent control plane.
It is not the service-to-service integration bus.
Helpdesk ↔ Knowledge uses direct versioned APIs or a separate future integration layer.
```

- [ ] **Step 4: Write ADR 0002**

Required decision:

```text
Current HTTPS pull is transitional.
Target is neutral Gateway WSS.
Legacy Helpdesk WebSocket is not retained.
No silent fallback to legacy transport.
```

- [ ] **Step 5: Write ADR 0003**

Required decision:

```text
One Git repository.
ALT uses RPM.
Windows uses MSI.
Common runtime and contracts; platform-specific service and package layers.
```

- [ ] **Step 6: Record baseline versions and production restrictions in `PLANS.md`**

Record the exact current repository SHA and the accepted ALT release/rollback versions from the existing production record.

- [ ] **Step 7: Run tests**

```powershell
python -m pytest tests/architecture/test_endpoint_platform_boundaries.py -q
git diff --check
```

Expected: tests that apply to current files pass; the future runtime import test is marked with a precise expected failure only until Task 2, not skipped indefinitely.

- [ ] **Step 8: Commit**

```powershell
git add docs/adr tests/architecture PLANS.md
git commit -m "docs: fix endpoint platform and agent transport boundaries"
```

---

## Task 1: Characterize the accepted ALT runtime before refactoring

**Files:**
- Create: `pc_agent/tests/runtime/test_current_gateway_characterization.py`
- Create: `pc_agent/tests/runtime/test_current_update_characterization.py`
- Create: `docs/agent/CURRENT_ALT_RUNTIME_BASELINE.md`

**Interfaces:**
- Consumes current `pc_agent/endpoint_gateway.py`, launcher, update runtime, and ALT deployment assets.
- Produces executable proof of behavior that must survive the headless split.

- [ ] **Step 1: Test current fixed Endpoint origin**

Assert that the accepted ALT runtime:

- uses `https://endpoint.sosnadmin.local`;
- validates the configured CA;
- never references the old Helpdesk endpoint;
- rejects credential failures terminally;
- retries only transient transport failures.

- [ ] **Step 2: Test current context command allowlist**

Assert only:

```text
context.baseline.collect
context.health.collect
context.network.collect
context.diagnostic.collect
```

are executed by the current ALT transport.

- [ ] **Step 3: Test current update and rollback invariants**

Assert:

- immutable selector read;
- artifact origin restriction;
- SHA-256 and size check;
- pending update atomic write;
- root updater path;
- startup outcome reporting;
- rollback target may be an existing immutable release.

- [ ] **Step 4: Run the characterization suite**

```powershell
python -m pytest `
  pc_agent/tests/runtime/test_current_gateway_characterization.py `
  pc_agent/tests/runtime/test_current_update_characterization.py `
  pc_agent/tests/test_self_update_runtime.py `
  pc_agent/tests/test_launcher_main.py `
  pc_agent/tests/test_launcher_portable_main.py `
  -q
```

- [ ] **Step 5: Commit**

```powershell
git add pc_agent/tests/runtime docs/agent
git commit -m "test: characterize accepted ALT gateway and update runtime"
```

---
