# Endpoint Agent V2 Implementation Plan — 06 Cutover Ci And Done

## Task 16: Retire HTTPS command polling after dual-platform WSS acceptance

**Files:**
- Modify: `pc_agent/transport/http_pull.py`
- Modify: config defaults
- Modify: `endpoint_server/gateway/routes.py`
- Modify: deployment configuration
- Create: `tests/gateway/test_http_pull_retirement.py`
- Modify: `PLANS.md`

- [ ] **Step 1: Prove ALT and Windows WSS-only acceptance**

- [ ] **Step 2: Disable HTTP pull for new enrollments**

- [ ] **Step 3: Keep a time-bounded rollback switch**

It is administrator-controlled, Endpoint-origin-only, and audited.

- [ ] **Step 4: Remove the switch after the rollback window**

- [ ] **Step 5: Remove dead HTTP command delivery routes**

Keep HTTPS enrollment, updates, artifacts, and service APIs.

- [ ] **Step 6: Commit**

---

## Task 17: Remove the inherited Helpdesk WebSocket path

**Files:**
- Modify or delete legacy sections in `pc_agent/ws_agent.py`
- Remove legacy transport/auth modules only after import and feature analysis
- Update PyInstaller legacy specs or move them under an explicitly unsupported archive path
- Create: `tests/architecture/test_no_helpdesk_agent_transport.py`
- Modify: source maps and `PLANS.md`

**Precondition:** ALT and Windows are running the neutral headless WSS core, and the future Helpdesk integration has a scoped Endpoint Platform service client plan.

- [ ] **Step 1: Write a failing repository scan**

Reject references in released core/package paths to:

```text
ws_ticket_v3
legacy Helpdesk WebSocket URL
TicketApiClient
connection-request Helpdesk enrollment
Helpdesk machine token
```

- [ ] **Step 2: Move reusable non-transport code**

Do not delete useful collector, update, consent, or Remote Assist implementation merely because it was previously called through Helpdesk.

- [ ] **Step 3: Delete legacy transport**

- [ ] **Step 4: Run full tests and build both packages**

```powershell
python -m pytest -q
python -m compileall -q endpoint_server endpoint_contracts pc_agent
git diff --check
```

Linux CI additionally builds RPM. Windows CI builds MSI.

- [ ] **Step 5: Commit**

```powershell
git add -A
git commit -m "refactor: remove inherited helpdesk agent transport"
```

---

# CI Matrix

Required jobs:

```text
contracts-and-server
agent-core-unit
agent-import-boundaries
linux-headless-build
alt-rpm-build
windows-headless-build
windows-msi-build
gateway-wss-integration
update-rollback-synthetic
full-regression
```

## `contracts-and-server`

```powershell
python -m pytest tests/contracts tests/gateway tests/context tests/updates -q
```

## `agent-core-unit`

```powershell
python -m pytest pc_agent/tests/runtime pc_agent/tests/transport -q
```

## `agent-import-boundaries`

Runs without Qt and blocks Helpdesk imports.

## `linux-headless-build`

Runs on Linux, builds PyInstaller artifact, runs `--verify`.

## `alt-rpm-build`

Builds RPM in a clean ALT-compatible build environment and inspects package contents.

## `windows-headless-build`

Builds the core and services on Windows.

## `windows-msi-build`

Builds MSI and runs static MSI contract inspection.

## `gateway-wss-integration`

Starts disposable PostgreSQL and the FastAPI server, connects simulated agents, tests replay and idempotency.

## `update-rollback-synthetic`

Runs filesystem-isolated update/rollback tests for both platform adapters.

---

# Release Gates

## Gate A — Headless core

Pass when:

- core imports without Qt;
- core contains no Helpdesk client;
- verify is network-free;
- current ALT characterization tests remain green.

## Gate B — Gateway WSS

Pass when:

- authentication, heartbeat, command delivery, replay, ACK/result idempotency, and reconnect pass;
- no Helpdesk fields are required;
- HTTPS pull remains unchanged for rollback.

## Gate C — ALT headless WSS

Pass when:

- accepted ALT pilot updates to the headless WSS core;
- baseline/health/network pass;
- a failed next release rolls back;
- WSS-only mode passes.

## Gate D — ALT RPM

Pass when:

- clean install, upgrade, repair, uninstall, and state preservation pass on disposable ALT;
- package contains no secret;
- signing procedure is documented.

## Gate E — Windows MSI

Pass when:

- clean install;
- protected provisioning;
- pre-login WSS connection;
- context collection;
- successful update;
- failed update;
- rollback;
- reboot;
- repair;
- uninstall;
- explicit purge all pass.

## Gate F — Legacy removal

Pass when:

- ALT and Windows use only Endpoint Platform WSS;
- no released artifact contains legacy Helpdesk transport;
- full repository regression passes;
- future Helpdesk integration is service-to-service, not direct-agent.

---

# Definition of Done

The implementation is complete when:

1. Endpoint Platform remains the only agent-facing system.
2. Endpoint Platform is explicitly not used as Helpdesk ↔ Knowledge relay.
3. The released agent starts from `pc_agent.runtime.main`, not inherited Helpdesk runtime.
4. The released core imports no Qt, Ticket API, Helpdesk auth, or legacy Protocol V3.
5. ALT and Windows use the same neutral core and contracts.
6. ALT connects through Gateway WSS and is installable by RPM.
7. Windows connects through Gateway WSS and is installable by MSI.
8. Windows service works before user login.
9. Both platforms pass Device Context collection.
10. Both platforms pass update, failed update, and rollback.
11. Device identity and credential survive update/rollback and package repair.
12. Current HTTPS command polling is removed after WSS rollback window.
13. Legacy Helpdesk WebSocket is removed from released code.
14. `web_ovpn` and Helpdesk use scoped service APIs.
15. No secret appears in source, package, logs, or verification evidence.
16. Production rollout remains a separate explicit decision after disposable acceptance.
