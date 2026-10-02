# Windows WSS Independent Recovery Updates Implementation Plan

> Use superpowers:executing-plans to implement and verify each task in this session.

**Goal:** Discover and stage Windows updates before any successful WSS handshake.

**Architecture:** One service-owned Windows recovery supervisor uses the existing HTTPS adapter and online stager. The root races its typed update-pending result against the WSS lifecycle, cancels and awaits every owned task, and keeps startup health proof strictly post-WSS.

**Tech Stack:** Python asyncio, aiohttp 3.13.3 (requirements/agent-core.txt), Windows SCM and existing immutable ZIP packaging.

**Spec:** User attachment `C:/Users/admin-2/.codex/attachments/e7251e81-d417-4106-8007-d80eff20caec/pasted-text-1.txt` (60 sections).

## Global constraints

- WSS is the sole normal Windows command plane; no privileged updater networking.
- Keep configured hostname, CA, bearer, same-origin artifacts and redirect rejection.
- Preserve hash, size, archive, ACL, manifest, candidate verification and WSS startup confirmation.
- One update poller; preserve Linux and explicit migration behavior.
- No mass production deployment; isolated local Windows canary authorized by user.

## Review focus

- Cancellation during download must remove incomplete temporary bytes without publishing pending state.
- Failed terminal-report delivery must delay rediscovery to avoid reapplying the same rollback candidate.
- A TLS exception subclasses network exceptions; classify trust failures first.
- Simultaneous terminal control failure and scheduled update must not lose either task exception.
- Tray heartbeat during reconnect must retain independent update status.

### Task 1: Reproduce and own independent recovery

Files: `pc_agent/platform/windows/update_supervisor.py`, `pc_agent/runtime/{application,lifecycle,status}.py`, `pc_agent/tests/runtime/test_windows_recovery_lifecycle.py`.

- [x] Add and run a failing test: default Windows WSS runtime, connect always unavailable, real online stager receives a valid 3.2.79 recommendation from its adapter; recommendation count must be positive before any handshake.
- [x] Add `RuntimeDependencies.create_service_tasks(settings, credential, publish_update_state)`; return service awaitables once after initialization. Add typed `UpdatePending` lifecycle signal; observe and cancel all tasks at root.
- [x] Add `WindowsRecoveryUpdateSupervisor.run()` with near-immediate report/check, shared 300-second update interval, bounded retries, fixed updater trigger and no WSS ownership.
- [x] Test connected, reconnect sleeping, hung connect, later reconnect, HTTPS outages and exactly one owner.

### Task 2: Secure failure and reporting semantics

Files: `pc_agent/update_adapter.py`, `pc_agent/transport/{base,websocket}.py`, `pc_agent/platform/windows/online_update_runtime.py`, `pc_agent/endpoint_gateway.py`, tray status and tests.

- [x] Test credential 401/403, TLS failure and redirect rejection before any staging; classify deliberately and preserve legacy adapter behavior with an explicit strict recovery mode.
- [x] Test failed/rolled-back reporting without WSS; preserve applied proof and rollback timeout tests. Defer discovery while durable failure report remains undelivered; verify canonical server terminal targets are excluded from recommendations.
- [x] Test protocol incompatibility as recoverable while local configuration, authentication, trust and unsafe origin remain terminal.
- [x] Test cancellation during HTTPS and download, temporary cleanup and no pending file.
- [x] Preserve independent tray values, add checking only if required by current contract and test heartbeat projection.

### Task 3: Release and acceptance

Files: `pc_agent/version.py`, release documentation, existing Windows build tools.

- [x] Increment 3.2.78 to 3.2.79 per current source; focused runtime/transport/adapter/online/updater/launcher/packaging/contract tests, compile and generated-contract checks.
- [x] Run full provider release gate against a frozen revision and report platform skips/failures explicitly.
- [x] Inspect complete diff, GitNexus impact and whitespace; commit only task files, build exact ZIP from that SHA and record artifact hash/source revision.
- [x] Isolated Windows acceptance: WSS-only failure while HTTPS stages candidate, offline updater applies, candidate WSS confirms; negative candidate rolls back where practical. Preserve working installed services.
- [x] Record all requested acceptance facts, CI run, residual risks and six explicit invariant answers; mark goal complete only after required work is verified.

## Acceptance limitation

The authorized local workstation runs the working Agent. A normal packaged candidate uses machine-wide named pipes even with separate data/install directories. Therefore the local exercise uses a source candidate with those facilities disabled and the exact packaged candidate only for offline --verify. This does not claim packaged online, SCM or LocalService acceptance. Full binary canary requires a dedicated Windows environment.

User subsequently authorized removal of the Agent from the test Windows VM (or local machine). Dedicated `endpoint-windows-canary-101-120` / `192.168.101.120` is reachable; MSI 3.2.78 removal returned 0 and left no Agent services. Packaged-candidate mode fails closed if Agent services exist and can now execute the exact EXE on that VM. Baseline remains the exact source runtime with injected process trigger; this is distinct from full LocalService/SCM acceptance.

## Verified completion evidence

- Release runtime source: `04665824c8d758607b76f06fe6686c4653eb3e6c`, Agent `3.2.79`.
- Frozen Windows full suite: `2331 passed, 45 skipped`; focused final suite: `208 passed`.
- Provider CI: `1524 passed, 8 skipped`, contracts/compile/whitespace passed: https://github.com/BorisDruzak/endpoint_platform/actions/runs/37004333632 .
- Exact ZIP SHA-256: `4cd3ea700825c6adf8c677a030dc268359080cbb62d133930993896f1a44402f`.
- Dedicated Windows VM positive: authenticated HTTPS download/staging before WSS handshake, real offline worker verification, packaged candidate handshake/proof and applied report.
- Negative: no handshake/proof; rollback restored selector3.2.78 and delivered rolled_back report.
- All temporary keys, credentials, candidate processes and disabled SID-fixture services removed; working operator Agent preserved.
- Scope is a source discovery baseline plus exact packaged online candidate, local TLS fixture and injected process service boundary. Full LocalService/SCM acceptance and production Console ONLINE state remain separate and are not claimed.
- No production deployment, mass rollout, MSI/Setup release or campaign promotion. `main` remains unchanged.
- Documentation-only closure commits do not change the verified runtime release source or ZIP.
