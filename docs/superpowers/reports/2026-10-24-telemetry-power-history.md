# Telemetry isolation and native power history — candidate 3.2.154

Acceptance date: 2026-10-24. Times in evidence are UTC.

Status: implementation, native builds, VM network/offline replay and the full 30-minute stability observation completed; limitations below remain explicit. This is a test candidate, not a production or fleet release.

## Source and scope

- Branch: `codex/telemetry-power-history`, isolated worktree from main `664333249025b41049cf9f9444bdeb7ee403917c`; remote main rechecked and unchanged.
- Frozen runtime: `f353a5ca2f1942d64f1c03bddd6ad9e85a527186`, `build(agent): freeze native shutdown candidate 3.2.154` (version and Windows context golden fixture).
- Immutable Windows runtime pin: `ca15b1b3298cd9a3c54051ae9319293835eafdcf`, `build(agent): pin native shutdown runtime 3.2.154` (`packaging/windows/initial-runtime-3.2.154.json`).
- Runtime source epoch: `1792861080`; Windows source inventory 219 files, retained artifact 118 files, tree SHA-256 `8580afa32277d2fe1115ffa800bd284f9846465f17aa5498550c7a99df25f705`.
- Endpoint staging provider/UI is deployed at `ab9f853b8fbc47b1ccb0c80fdab7a3a30e42c6c9`, database migration `0039_power_source_state`. All subsequent reliability and native-evidence fixes are client changes and require no additional provider migration.
- No production deployment, fleet campaign, shared-branch push or merge. Helpdesk source was read-only. Unrelated original-checkout changes were preserved.

## Resulting behavior

Validated optional activity, browser, sensor-health and security report rejection rolls back its own transaction without closing control connectivity. Updated peers negotiate correlated, nonfatal results; legacy peers receive no new frame. Authentication, invalid framing, unsupported protocol messages, command-state violations and genuine transport failures retain their fatal behavior.

Power collection is independent of activity/DLP policy. Protected local storage commits native facts and checkpoints together, replays after reconnect and removes facts only on exact committed disposition. Limits remain 30 days, 10,000 events, 5 MiB local payload and 128 events/60 KiB per envelope. No rendered OS messages, native XML, credentials or command lines are retained in power facts.

Windows uses structured System event metadata and native notifications, with a killed/reaped, bounded private reader process. Linux uses boot identity, trusted journal metadata and logind notifications without elevating the main agent to root. Source availability, coverage, loss and checkpoint resets are explicit. A missing or changed cursor anchor conservatively replays retained history rather than claiming continuity.

The console separates last connection, last observed activity and last OS fact. Network silence alone remains `Нет связи — причина неизвестна`; an old shutdown/sleep cannot override subsequent known communication. A shutdown/sleep request is not proof of completed physical power-off. Activity gaps and active/idle calculations are unchanged.

## Source reviews and regression evidence

Tasks 1–4 passed independent specification/quality review. Whole-branch review found three Important issues; all were corrected in one wave and independently re-reviewed as addressed, with no new findings:

| Commit | Change and files | Regression |
|---|---|---|
| `d9f584d9e2c7c813668adf9ff3bb2a5cf2b98cfb` — `fix(power): size replay batches using actual JSON wire bytes` | `pc_agent/transport/{base,websocket}.py`, power spool, spool/transport tests, CODEMAP | Real spool → actual aiohttp serializer → provider parser; near-limit batches drain in order and remain within 61,440 wire bytes. RED 2 failures → GREEN. |
| `8779e8e5609757ce5714013c3eb57fb5e7d8aa7c` — `fix(power): validate Windows cursor identity before replay` | Windows power adapter, native tests, collection architecture/CODEMAP | Five modeled native cases: overlapping log generation, legacy checkpoint, missing anchor, unchanged generation and later legitimate live boot. RED 5 failures → GREEN; bounded replay/checkpoint reopening verified. No destructive live log-clear experiment. |
| `445122d157f941c8151bf926426be533de3748d7` — `fix(security): apply regrouped results to pending event IDs` | Security runtime/tests, provider regression, telemetry architecture/CODEMAP | Real in-memory provider plus transient local SQLite failure across the 24-hour boundary: previously disposed IDs are validated but ignored, pending siblings advance once and later events drain. RED 1 failure → GREEN. |

Actual candidate 153 offline testing then exposed a separate Linux acceptance gap: systemd 258 emits successful `UNIT_STARTED` for `shutdown.target`, while the collector queried only `UNIT_STARTING`. Commit `f03e540f3912dacb17cbde803fec508c90f73265`, `fix(agent): recover retained ALT shutdown target evidence`, admits the additional native message only behind exact trusted UID0/PID1/init.scope/shutdown.target checks. Projection-version2 atomically triggers one bounded retained-history replay, preserves the current boot and prevents repeated resets. The captured metadata fixture uses synthetic boot/cursor identity. RED 3 failures → GREEN 12 tests, covering suite 55 passed, Ruff passed; independent scoped review 12 passed with no findings. Rebuilt candidate 154 native offline acceptance now proves the previously missed Linux shutdown transition. Physical power-off remains unproven by that transition alone.

Primary implementation commits: gateway `364ff6c21f9e6d6410fcb81125667135d9aa3c69`; provider `5de4150bbaa585809d5bc271a026236146a55a82` and ordering `b8a9825c14c75e2e79b5dffe8f0c0f84cd9fcfb2`; native collection `64f2e70fc4b1ffaaca1d554cae9a8ef56dda121f`, `a649789fd637d97e2fdc983a5788a664ad7664b5`, `2ce4b690b813267a54033e17580637dd88b5af8f`; console `bd64f6b5d587d9ca234a88767e4e8c9ed4a75b96`.

GitNexus was consulted before architectural exploration and review. Its indexed commit matched the main baseline; local source/diffs supplied the branch additions. Console functionality is additive; existing Helpdesk/web consumers were checked at their published contract boundary. No manual synchronization or generated cross-link edits were made. Context7 guidance was used where available; after quota exhaustion, API-specific work used official documentation.

## Verification

`PY` below denotes the task's Python 3.12 test environment; native builders used separate locked environments.

| Command/check | Observed result |
|---|---|
| ALT Linux exact packaging commit `ca15b1b`: `python -m pytest tests pc_agent/tests -q --basetemp=/root/epp154-full -o faulthandler_timeout=120` | **4827 passed, 1084 skipped**, 276.20 s, exit 0. Four upstream Starlette/httpx deprecation warnings. Platform and optional PostgreSQL skips remain explicit. |
| Windows candidate 153 source: `PY -m pytest pc_agent/tests/windows -q` | **2028 passed, 1 skipped**, 163.92 s. Candidate154 changes only the Linux collector and version; exact source inventories prove the Windows collector/runtime/security/transport bytes unchanged. This is not an exact154 full Windows-suite run. |
| Review-fix affected gateway/transport/power/security suite | **297 passed**, 52.95 s; telemetry result contracts **2 passed**. |
| Independent scoped re-review reproductions | **9 passed**, including actual aiohttp wire serialization, native anchor cases and real-provider regrouping. |
| ALT shutdown correction, focused and independent review | **55 passed**, independent **12 passed**; Ruff check/format passed. |
| Runtime pin/foundation/context checks: `PY -m pytest tests/packaging/test_initial_runtime_contract.py pc_agent/tests/windows/test_foundation_upgrade_source.py pc_agent/tests/windows/test_context_profiles.py -q` | **26 passed**, 5.71 s; full source/stage/toolchain reconciliation passed. |
| Context tests and updated Windows golden fixture | **59 passed, 3 skipped**. |
| Actual PostgreSQL 16 migration tests on disposable role/databases | **38 passed**; disposable databases/role removed. Staging migration 0039 applied with private database backup. |
| Frontend tests/typecheck/build | **56 tests passed**; typecheck/build passed. Deployed staging UI source unchanged by later client fixes. |
| Playwright fixture-backed browser checks | Desktop 1440×1000 and mobile 390×844, fleet/detail/history/analytics, pagination/keyboard, no overflow or console errors. Dense timeline markers can overlap visually; keyboard selection and full-text history remain usable (reviewed nonblocking limitation). |
| `PY -B tools/contracts/generate_contract_artifacts.py --check`; complete-range `git diff --check` | Passed; checked again during review and fix verification. |

Earlier general Windows diagnostic runs containing POSIX-only fixture failures were not represented as passing. Logger-state, Linux policy-state and live-directory timestamp test isolation defects were repaired and reviewed; final native-platform results above supersede those runs.

## Native packages

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `EndpointAgentSetup-3.2.154-x64.exe` | 145711496 | `b5345d8d3a1023f5129184e9fdf5bcbfb9c05bee33b7abedc83104d8e354bf1b` |
| `EndpointAgent-3.2.154-x64.msi` | 104038400 | `7f9cb60c514b9dc06b2750c7cf91b83c540acca3387ebeb7ca23fee847a73f9b` |
| `endpoint-agent-3.2.154-alt5.x86_64.rpm` | 28580217 | `f6ae291a44168320f4e0d8c949cf6bdfd87a1639f9f9c292767dc042a0a8588b` |
| `endpoint-agent-user-sensor-3.2.154-alt5.x86_64.rpm` | 51840 | `214994f3f1e6e1f8c294747c8ac96692699e99f2c0e02626e1038883c29ec74d` |

Windows Setup/MSI Authenticode signatures are Valid with the expected organization publisher and DigiCert timestamp. Canonical privileged-bootstrap/offline-updater inspections and `--verify-offline` passed. WiX 4.0.6 was selected through the existing version-pinned shim; no global toolchain replacement.

ALT Core and exact-version User Sensor were built by the unprivileged dedicated builder with the locked toolchain. RPM digests and native transaction dry run passed. These generic test RPMs are not a published signed ALT distribution kit.

Retained local artifacts: `output/agent-3.2.154/linux/` and `output/agent-3.2.154/windows/`; signed Windows releases are in the dedicated `C:/ep-power154/releases/` build root. Raw logs, public release sidecars, source/stage evidence and inspections remain outside Git. No private signing key or enrollment secret was exported.

## VM acceptance

Dedicated Linux VM107 and clean Windows VM134 use verified-TLS Endpoint staging. Their permanent credentials stay on the guests. Test enrollment was single-use and immediately revoked; Windows power facts were delivered before policy assignment, then a device-only policy with all continuous sensors disabled was applied.

| Case | Observed result |
|---|---|
| Linux 153 → 154 native RPM update, Core + exact matching User Sensor | Transaction exit 0, selected source `f353a5c`, private state/runtime backup verified, credential and device identity unchanged, service active, power source READY and queue drained. |
| Windows clean signed 152 Setup | Exit 0, native installed authority/current runtime verified, authenticated staging connection and native history delivered. |
| Windows 153 → signed 154 ordinary Setup upgrade | Preflight READY, applied policy verified before submission; one normal attempt, exit 0 in 293.56 s, staged phase accepted, no running recovery task, selected/foundation 154 and fresh control connection. Private backup/snapshot retained; permanent identity unchanged. |
| Same-boot service restart | Windows PID changed, boot time unchanged, history stayed at the same 22 facts. Linux service-only restart likewise added no OS startup. Later version changes did not invent install-time boots. |
| Normal OS shutdown/start | Both native histories recovered OS shutdown transition and startup, ordered by occurrence time rather than reception time. |
| Windows hibernate/resume, candidate 153 (identical Windows implementation in 154) | Passed: boot time and service/Core PIDs preserved, native `OS_RESUMED` delivered, source READY, queue drained. |
| Windows S3 | OS entry and QMP suspended state observed. Direct wake attempt was followed by VM exit and an OS unclean-shutdown report after startup; direct S3 resume is **not accepted**. Hybrid/hibernation recovery later produced genuine resume evidence. Cause of the failed direct wake remains UNKNOWN. |
| Linux S3/s2idle | Entry was attempted; a usable native resume was not verified on this fixture. One early harness attempt had an expired RTC alarm before actual entry and is invalid as wake-support evidence. Corrected precise-timer/native-machine attempts still did not establish resume. No successful-resume claim. |
| Windows hybrid/Fast Startup request | The requested hybrid shutdown was followed by native full-boot evidence; actual Fast Startup activation is not claimed. Parser fixtures cover the distinct BootType cases. |
| Network loss without a power action | Passed on154: both links down 181.235s; at 105s both summaries UNKNOWN/offline and exact history IDs unchanged. Linux QGA and five Windows local samples prove unchanged boot/service while the link was down. |
| Shutdown/reboot while offline and subsequent replay | Passed on154: planned reboot 130s into the outage, both native histories delivered startup and shutdown **transition** facts with occurrence times inside the outage. Linux queue 4 while offline; both queues 0 after reconnect. Only owned link flags restored, exactly matching baseline. |
| Thirty-minute stability, 30-second samples | **Passed**:61 guest and61 server samples over 1800 seconds; no missing/error samples, reconnect, service/Core restart, new power fact, queue backlog or loss. Details below. |

Local Windows and Linux reset diagnostics each incremented once when older checkpoints were conservatively upgraded to the Windows native-anchor format / Linux projection version2; this is not evidence of a destructive OS log-clear operation. The final observation compares counters against those baselines. During the quiet window, bounded 35-minute OS sleep-inhibition requests hold both test VMs awake without synthetic user activity or global preference changes; these temporary requests are released after sampling.

Actual staging WSS/PostgreSQL rejection test used one authenticated connection from a bounded canonical-source harness at `6367369a3c813a4cfaa2b430019441c00e4d4e7f` (agent152). It temporarily stopped the installed Linux daemon and restored it in finally; it did not replace that installation or inject faults into the final154 daemon. Three invalid sensor-health inputs received correlated nonfatal rejection; subsequent heartbeat and the real health command completed on that same session. Read-only PostgreSQL assertions confirmed same-session delivery, succeeded result, one validated snapshot and zero persisted rejected report IDs. The original Linux service was restored active. This bounded accelerated probe is separate from the 30-second production cadence and stability test.

## Full thirty-minute observation

Both installed 154 runtimes were observed from 17:27:34 to 17:57:34 UTC. Each collector saved61 samples at 30-second cadence. Guest monotonic span 1800.016s (maximum interval 30.016s); independent staging DB span 1800.031s (maximum interval 30.026s). Guest sampling completed with exit 0 and zero errors.

| VM | Constant service/Core PID | Maximum presence age | Core RSS range | Average CPU, one core | Queue peak/final |
|---|---|---:|---:|---:|---:|
| Linux | 1028 / 1381 | 6.519s | 72.22-73.91MiB | 0.678% | 0 / 0 |
| Windows | 3228 / 4292 | 8.513s | 80.79-81.59MiB | 1.451% | 0 / 0 |

Presence age is measured from DeviceSession.last_seen_at. The same session UUID and total session count persisted throughout on each device; no session closed or was replaced. Boot identity and process start times stayed unchanged, Linux NRestarts stayed 0, and native power-history totals stayed 44/61. Both sources remained READY with fresh coverage reports. Loss/rejected/overflow/expired counters stayed 0; each pre-existing migration reset counter stayed 1. Linux CPU covers the service cgroup including children; Windows covers persistent service+Core and excludes short-lived native-reader CPU. These measurements establish the bounded 30-minute result, not long-term fleet acceptance.

Read-only final API capture also confirmed both devices online, sources READY and unchanged power-history totals. No power/service/network/hardware changes occurred during the observation. Bounded sleep-inhibition requests were released afterwards.

## Historical upgrade limitation and preserved evidence

The original Windows VM123's 149 → 152 forward upgrade reached its trial, but that newly enrolled staging device had no assigned policy, so APPLIED policy acknowledgement could not arrive. The original owner timed out and attempted rollback. The immutable **old 149** restoration helper then rejected the protected provisioned-origin ACL, leaving mixed native registration/authority state. No guard was reset, recovery CLI replayed or old acceptance slot reused.

The exact additional protected origin policy is admitted by the reviewed source fix `5d96f9ee1d2ff97b4317b16c096d281b60e9264b`; immutable historical 149 bytes were not rewritten. The failed VM remains stopped and preserved in a dedicated failure snapshot. All unrelated historical snapshots remain intact. A separate pre-agent clean fixture was used for fresh-install and modern-upgrade acceptance.

This old-helper rollback failure remains an explicit **fleet/release limitation**. Fresh installation and successful modern 152 → 153 → 154 upgrades do not establish safe 149 rollback or waive any historical timing/recovery gate.

## Operational decisions and costs

| Decision | Reason / cost if wrong |
|---|---|
| Sequential implementers with independent task reviews; root VM preparation in parallel | Avoid shared source mutations. Incorrect task boundaries would require rework; all source changes were reviewed against the actual diff. |
| Reuse the existing isolated Endpoint staging provider | Preserves production scope and real TLS/provider contracts; staging availability remains a test dependency. Private database backups precede migrations/deployments. |
| Bound Windows native reads in a fixed private subprocess | Gives genuine kill/reap/process-exit guarantees; costs a short-lived reader process and bounded transient memory/CPU. |
| Retire unpublished 150 metadata and allocate fresh immutable 151/152/153/154 identities | The first 150 attempt incorrectly normalized the raw Windows entry point before the canonical MSI builder, which owns that normalization. It stopped before MSI publication/install. Retiring its unpublished metadata in a forward commit and keeping its evidence avoids ambiguous same-version bytes; 151-154 use the original raw-stage flow. Cost: additional builds and immutable version identities. |
| Compare stable directory identity/security in the isolated installer harness | Active-agent directory mtime/ctime alone is not proof of installer mutation. Full leaf metadata and path-rewrite guards remain; volatile directory-only timestamp changes are not detected by this snapshot. |
| Preserve failed VM123 and use independent clean VM134 | Avoids modifying protected failed recovery authority; costs one additional test VM/50 GiB virtual disk allocation. It does not repair or certify old 149 rollback. |
| Review source before the final quiet observation | Exposed three reliability defects before spending the stability window. Any subsequent runtime defect would still require new evidence/builds; the observation was not waived. |
| Rebuild 154 after actual ALT metadata exposed a missing shutdown transition | Expanding the message filter alone would strand retained facts behind an advanced cursor; an atomic versioned replay costs one reset and a fresh native build/install/network gate. |
| Preserve report WIP outside tracked source during the canonical build | The builder correctly rejected an untracked report. Its exact hash-verified bytes were moved to ignored task scratch, then the unmodified canonical build succeeded; no guard bypass or artifact identity rewrite. |
| Restore temporary power hardware settings before stability | Removes fixture configuration changes from the quiet window. Failed/unverified S3 remains a documented limit rather than an assumed pass. |

The earlier automatic staging-command rejection supplied no explanatory reason. The denied combined script was not retried through encoding or another tool. Explicit target-checked granular operations subsequently succeeded; no operator manual action is pending. A reconnaissance `lxc --version` unexpectedly invoked the distribution installer wrapper; only its newly installed snap packages were removed, and service health was verified afterward.

## Evidence and cleanup

Ignored evidence includes `output/power-acceptance/`, `output/task5-live-telemetry-db-evidence.json`, native build/test logs, source sidecars and private guest backups. Review/fix reports are in the plan's ignored SDD directory. These paths contain no committed credentials; production infrastructure and human accounts were not changed.

Final network/stability evidence is retained below. The fixture administrator is disabled, every session revoked, an append-only audit event recorded and its private plaintext credential file removed. Human administrators and device-only policy/history references remain intact. Eight owned Windows acceptance tasks were removed, the Linux inhibitor released, and both agent services remained active. Original VM power hardware/NIC fields were verified restored; historical failed VM123 remains stopped with its snapshot/private backups intact. Canonical recovery tasks were not changed.

Endpoint staging API/worker, Nginx and PostgreSQL remain active; current provider/UI release is ab9f853b8fbc. Settings-derived read-only SQL confirms migration 0039. Helpdesk staging still has PID 119931/start 06:06:45UTC, unchanged. The first cleanup helper invocation omitted PYTHONPATH and failed before imports/DB changes; the corrected source-path invocation completed and its result was verified. A guessed direct psql database name did not exist; final migration verification used the service's actual Settings instead. Neither failed read/import attempt is represented as a passing check.

| Retained raw evidence | SHA-256 |
|---|---|
| `output/power-acceptance/network-offline154.json` | `2f66fcacaaf654871fc738d03b3374f4a8c2c040f8e43d9731b12147cb360ce1` |
| `output/power-acceptance/stability-guests-final154.jsonl` | `e0c632ce6d59fa398742155b88a88e82414c47c8c3433ee7cb786c225bbbf107` |
| `output/power-acceptance/stability-server-final154.jsonl` | `8467d02194efe6f12bfbf96dab5ecc48c1fc1f22be9f191e0e913ffc39a55863` |

Summary: `output/power-acceptance/stability-final154-summary.json`; final API snapshot: `final154-after-stability.json`; fixture retirement: `staging-fixture-cleanup154.json`. Full diff/contract drift checks passed; the branch/worktree are retained for review without push or merge.

Official references used for native harness/API checks: [Windows SetSuspendState](https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-setsuspendstate), [Windows shutdown](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown), [aiohttp 3.13.3 WebSocket JSON serialization](https://docs.aiohttp.org/en/v3.13.3/client_reference.html#aiohttp.ClientWebSocketResponse.send_json), [Windows structured event consumption](https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events).
