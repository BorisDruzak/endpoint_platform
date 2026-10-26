# Telemetry isolation and power history implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Reject optional telemetry without dropping control connectivity and show durable, OS-evidenced power history on Windows and ALT Linux.

**Architecture:** Isolate optional-message transactions and local collection faults. Negotiate new nonfatal telemetry results and a policy-independent power-event channel; persist power events locally until exact server disposition, store server history in DeviceEvent and current source coverage separately. Present connection availability independently from historical power evidence.

**Tech Stack:** Python 3.12, Pydantic 2.12.5, SQLAlchemy 2.x, aiosqlite 0.22.1, aiohttp 3.13.3, native Windows/systemd APIs, React 19.3/TypeScript.

**Spec:** `docs/superpowers/specs/2026-10-24-telemetry-isolation-power-history-design.md` (approved by user 2026-10-24).

## Global Constraints

- Start from origin/main `664333249025b41049cf9f9444bdeb7ee403917c` in this dedicated worktree; preserve unrelated source changes and other worktrees.
- 30-second heartbeat and 90-second presence semantics stay unchanged; offline alone never means powered off.
- Optional telemetry domain/collector failures are nonfatal; authentication, malformed framing, command-state violations and real transport failures retain their fail-closed behavior.
- Do not use the existing fatal `error` frame for nonfatal telemetry results; negotiate support before emitting new frames.
- Power history is policy-independent: 30-day retention, 10,000 local events, 5 MiB payload, 128 events/60 KiB per batch, metadata below 2 KiB.
- No raw OS message/XML, command lines, credentials or personal data in power facts, logs, reports or fixtures.
- Commit locally before advancing native cursor; delete delivered events only after exact committed server disposition; late facts cannot roll current state backward.
- Do not change DLP/activity 24-hour acceptance bounds or activity calculations.
- Use dedicated nonproduction VMs for reboot/sleep/network/service tests. No employee workstation power transitions, production deployment or recovery-slot operations.
- Build both platform packages, test them on VMs, then run a 30-minute stability observation with 30-second samples and save raw evidence.
- Tests ran in the isolated worktree environment `.superpowers/sdd/2026-10-24-telemetry-power-history/test-env/Scripts/python.exe` (Python 3.12.14), preserving the original checkout environment. Native package inputs use the existing locked builders; actual Linux native versions are recorded in the acceptance report.

## Review Focus

- Optional collector failure races with a transport/authentication failure: collector isolation must not hide terminal control failure (Task 1).
- Mixed durable batches and lost ACKs: valid siblings persist once and permanent poison events do not block replay (Tasks 1–3).
- Reconnection/service restart within one OS boot and cancelled shutdown requests must not create false boot/offline-power facts (Tasks 2–3).
- Source log rollover, clock skew, missing journal permissions and out-of-order history explicitly reduce coverage instead of producing certainty (Tasks 2–4).
- A later silent network failure must not inherit an old sleep/shutdown hint after known communication (Tasks 2, 4).

## Execution and ledger

Use subagent-driven development for Tasks 1–4, one implementer at a time, independent task review after each. Root prepares VM/build acceptance in parallel as an independent infrastructure task. Record exact interfaces and any engineering rulings in `.superpowers/sdd/2026-10-24-telemetry-power-history/progress.md`. User already authorized execution; continue through all tasks and acceptance without another plan approval prompt.

### Task 1: Isolate optional telemetry failures end to end

**Files:** `endpoint_server/gateway/ws_routes.py`, focused new gateway helper if needed; `endpoint_contracts/gateway_ws.py`, `endpoint_contracts/telemetry_results.py`; `pc_agent/runtime/lifecycle.py`, `pc_agent/runtime/application.py`, owning activity/browser/sensor-health send loops, `pc_agent/security/{runtime,spool}.py`; gateway/agent/contract tests; generated schemas via `tools/contracts/generate_contract_artifacts.py`; relevant protocol docs.

**Interfaces:** Add `endpoint.telemetry-results.v1` and optional `GatewayHelloV1.protocol_features` (empty default for older peers). `TelemetryResultV1` has report kind, report UUID, original report sequence, disposition (`accepted|retry_later|rejected`), safe bounded reason code and exact event IDs for a security batch/subset. Emit `telemetry_result` only to agents advertising the feature; agent handlers consume it without terminating. Record the exact chosen model/signatures in the task report for later tasks. Legacy agents continue receiving no new frame for rejected optional samples. Existing security ACK remains commit-before-ACK; updated peers support partial valid delivery and permanent rejection without corrupting exact-ACK semantics.

- [x] Write failing integration tests showing stale/future/policy-mismatched sensor-health/activity/browser reports leave the same session usable for subsequent heartbeat and command; no partial writes. Keep disabled/unnegotiated framing fatal.
- [x] Add failing tests for nonfatal result correlation, mixed security batches, ACK loss/replay, permanent rejection counters and expected local collector failure while heartbeat continues. A simultaneous real transport failure must still propagate.
- [x] Run targeted tests and record expected RED failures before code.
- [x] Implement narrow per-report transaction/rejection boundaries, negotiated results, durable sender dispositions, and expected collector retry/degradation. Preserve cancellation and avoid broad runtime exception suppression.
- [x] Regenerate and verify canonical schemas; run affected gateway, security, runtime, transport and contract suites; inspect all failures.
- [x] Self-review, `git diff --check`, stage only Task 1 files and commit `fix(gateway): isolate optional telemetry failures`.

### Task 2: Power contracts, server ingestion and evidence projection

**Files:** create `endpoint_contracts/power_events.py`, `endpoint_server/power/{models,ingestion,projection,routes,retention}.py`; extend gateway contract/parser/route, model registration, maintenance worker, console response types; migration `0039_power_source_state.py`; new power/gateway/contracts tests; generated schemas and affected OpenAPI artifacts.

**Interfaces:** Add `endpoint.power-events.v1`. `PowerEventV1`: UUID event identifier, native event kind from spec, aware occurred/observed times, bounded boot ID/source/native record ID, evidence (`transition|request|reported`) and sleep subtype if applicable. `PowerSourceStatusV1`: source availability (`READY|DEGRADED|UNAVAILABLE|UNSUPPORTED`), reported time, coverage start, bounded loss/reset counters. `PowerEventBatchV1`: batch UUID, up to 128 unique power events and source status (empty events allowed for periodic coverage). `PowerEventAckV1`: matching batch UUID, persisted time and one per-event disposition (`accepted|retry_later|rejected`) with safe reason. ACK covers exact submitted IDs once; server transaction commits before sending.

Create a current source-status row per device (separate from OS event history). Reuse `DeviceEvent(category='power', profile='power_v1')` for accepted facts; unique native source/event identity prevents duplicate boot/replay. Implement `GET /api/admin/console/devices/{device_id}/power` with current connectivity, source coverage, latest power evidence and paginated bounded history; reuse projection in optional fleet/device summary fields and activity timeline power markers. Admin auth/cache controls follow existing console routes.

- [x] Write RED tests for exact duplicate vs conflicting ID, per-event rollback/mixed batches, future/expired time, no policy requirement, unauthorized/non-negotiated frames, empty status batch and ACK-after-commit.
- [x] Write RED projection tests: online wins; service reconnect is no boot; cancelled request cannot label shutdown; newer known communication invalidates old sleep/shutdown hint; reversed arrival order cannot reverse state; unsupported/missing source remains unknown.
- [x] Implement typed bounded contracts, provider ingestion/current source state, projection and retention. Add indexed PostgreSQL migration only for the source state table and verify a single head.
- [x] Test PostgreSQL migration/ingestion when test DB available; run SQLite unit suites regardless, regenerate contracts, check existing response compatibility. Preserve old activity metrics.
- [x] Update protocol/server docs, inspect diff/check, and commit `feat(power): persist OS power evidence and source coverage`.

### Task 3: Durable agent power collection on Windows and ALT Linux

**Files:** create `pc_agent/power/{spool,runtime}.py`, `pc_agent/platform/windows/power_events.py`, `pc_agent/platform/linux/power_events.py`; extend `pc_agent/runtime/{application,lifecycle}.py`, `pc_agent/transport/websocket.py`, actual Windows service host and relevant Linux packaging/helper only if required; agent power/native/runtime tests and CODEMAP/docs.

**Interfaces:** Consume Task 2 models. `PowerEventSpool` persists events and native cursor atomically, with independent 30-day/10,000/5-MiB limits, loss counters, exact disposition validation and quarantine for permanent rejects. `PowerEventRuntime` collects independently of network, sends/retries only after negotiated power support, records source health and consumes `PowerEventAckV1`. Native adapters produce bounded pages of structured facts and a cursor; they never mark an agent process restart as OS startup.

- [x] Read local AGENTS routing and available docs; verify pinned external/native APIs with Context7/official OS docs before API-dependent code. Use real provider+event metadata fixtures, never localized rendered-message heuristics as proof.
- [x] Write and run RED tests for spool crash/ACK loss/duplicate/conflict/overflow/expiry/cursor reset, offline multi-day replay, source availability, bounded reads, and failed collector without heartbeat loss.
- [x] Write and run RED native tests for boot, shutdown-start vs cancellable request, suspend/hibernate/resume, unclean-shutdown report, same-boot agent restart, journal rollover and clock skew. Verify actual Windows service-launcher controls before adding notifications.
- [x] Implement protected durable spool/runtime, bounded native collection, current source diagnostics and runtime/transport composition. Keep main agent unprivileged; if journal access needs a helper use minimal fixed metadata boundary and explicit package changes.
- [x] Run affected native/runtime/transport/security tests; update docs/CODEMAP; inspect/check diff, commit `feat(agent): replay native power events across reconnects`.

### Task 4: Console power labels and timeline

**Files:** `webapp/src/{FleetPages,ActivityAnalyticsPage}.tsx`, relevant API types, focused new power status component, styles only as required; server console timeline extension if not finished by Task 2; frontend/server presentation tests.

**Interfaces:** Consume Task 2 power API/projections; retain `online` behavior. Show independent last connection, last activity and last power evidence. Use approved Russian text: `Нет связи — причина неизвестна`, `Последнее событие: переход в сон`, `Последнее событие: завершение работы ОС`. Unknown/unsupported coverage stays explicit; power history is separate from employee active/idle metrics.

- [x] Write RED UI tests for fresh online + old shutdown, unknown offline, sleep/shutdown evidence, unavailable source, delayed history and history pagination. Verify timelines preserve unknown activity gaps.
- [x] Implement in the existing console layout with accessible labels; avoid a redesign.
- [x] Run frontend tests/typecheck/build and affected server console tests. Inspect rendered pages via existing Playwright MCP with a local fixture-backed test provider.
- [x] Inspect/check diff and commit `feat(console): distinguish power evidence from lost connectivity`.

### Task 5: Builds, VM transition acceptance and stability gate

**Files:** focused acceptance scripts under `tools/` if reusable; task-specific evidence under ignored output and a concise tracked `docs/superpowers/reports/2026-10-24-telemetry-power-history.md`; release metadata only where required by existing builders.

**Interfaces:** Use existing canonical Windows/ALT builders and signing workflows. Keep packages as test candidates, not published fleet updates; don't change production selectors. Use an isolated test provider reachable over verified TLS to exercise the changed server without production rollout. The current Linux SSH alias may be stale; QGA/network inventory can establish the dedicated VM's current address before testing. Document actual package version/source hash/digests.

- [x] Run relevant suites, contract drift checks, full project pytest command, frontend test/typecheck/build and required packaging checks. Report pre-existing/platform skips and any failures by name; never silently ignore.
- [x] Build Linux and Windows candidates with existing locked Python3.12 toolchains; validate package metadata, signatures where existing test workflow requires them and archive hashes.
- [x] Install on dedicated Linux and Windows test VMs, preserving existing identity unless an isolated test instance/provider needs distinct identity. Test policy-independent events, service-only restart, OS reboot/shutdown/start, sleep/resume/hibernate when VM supports it, network interruption with no false power fact, offline replay and rejected telemetry while commands/heartbeat still work. Capture native events + server rows + session IDs, not just logs asserting success.
- [x] After transition tests run a 30-minute stability gate: every 30 seconds capture boot ID, service/core PID/restarts, heartbeat age/session ID, queue counts/rejections, power source state and CPU/RAM. Expect no spontaneous reconnect/service crash, bounded memory/queues and delivered events. Save raw JSONL and summarize gaps/limitations.
- [x] Dispatch independent whole-branch review, address important findings with RED→GREEN verification, rerun affected checks. Update report with exact evidence and known unsupported VM transitions.
- [x] Inspect full diff, `git diff --check`, exact staging and no secrets/artifacts; commit verification report. Keep worktree available for review; report commit SHAs/messages/files, tests, build paths and VM/stability outcomes. No merge, shared-branch push or production rollout is included without additional user instruction.
