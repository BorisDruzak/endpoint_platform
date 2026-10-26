# Endpoint Agent 3.2.154 — 24-hour stability acceptance

**Result: PASS for the dedicated Linux and Windows agents and their staging connection.** Production observations below are separate and include disconnects.

Window: **25 October 2026 15:00 to 26 October 2026 15:00 Asia/Yekaterinburg**, corresponding to 2026-10-25T10:00:00Z–2026-10-26T10:00:00Z. The original deadline was preserved.

## Source and test scope

- Branch `codex/telemetry-power-history`; runtime source `f353a5ca2f1942d64f1c03bddd6ad9e85a527186`, immutable packaging pin `ca15b1b3298cd9a3c54051ae9319293835eafdcf`. Both guests reported exactly 3.2.154 and that runtime source in every sample.
- Dedicated Linux VM107 and Windows VM134 used the existing verified-TLS Endpoint staging provider/UI release `ab9f853b8fbc47b1ccb0c80fdab7a3a30e42c6c9`. Production was queried read-only through aggregate/session-fingerprint observers.
- This test changed no agent implementation, installed candidate, device identity, policy, production service, Helpdesk service or recovery authority during the window. No fixes or runtime interventions were needed on the two test agents.
- Native observers ran independently of Codex. Samples every 30 seconds; three-hour checkpoints and scheduled reviews at 3/6/9/12/15/18/21/24 hours. Bounded native sleep-inhibition requests held the test VMs awake without synthetic activity or global power-policy changes.

Prior source reviews, unit/integration/browser checks, builds/signatures, native transition tests and historical limitations are documented in [the implementation acceptance report](2026-10-24-telemetry-power-history.md). They were not represented as newly rerun unit suites in this operational test.

## Complete observation and sampling verification

All **8643 records** (2881 per observer) were read from sealed exported JSONL files. Sequences were exactly 0..2880, without missing/duplicate/reordered slots or sampling errors. Each file covers the fixed 86400-second schedule. Exact sample timestamps differ by at most 0.030 seconds from that span due to subsecond scheduling jitter; no shortened/rescheduled test was substituted.

| Observer | Samples | Actual first-to-last span, seconds | Maximum interval, seconds | Maximum trigger lag, seconds |
|---|---:|---:|---:|---:|
| Linux | 2881 | 86399.999975 | 30.007879 | 0.004876 |
| Windows | 2881 | 86399.970349 | 30.248744 | 0.257945 |
| Server | 2881 | 86400.000019 | 30.001312 | 0.001498 |

Each native three-hour checkpoint was validated at 361/721/1081/1441/1801/2161/2521/2881 records. Both systemd observers exited 0 with Result=success/NRestarts=0; the Windows task completed with result 0.

## Agent and connection results

| Metric | Linux | Windows |
|---|---:|---:|
| Constant service/Core PID | 1028 / 1381 | 3228 / 4292 |
| Boot/service/Core restarts | 0 | 0 |
| WSS replacements / session-count changes | 0 | 0 |
| Maximum presence age, seconds | 30.074 | 30.070 |
| Power source states | READY throughout | READY throughout |
| Maximum provider source age, seconds | 5.112 | 6.462 |
| Queue peak / final | 0 / 0 | 0 / 0 |
| Loss / rejected / overflow / expired | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Native reset counter | 1 throughout | 1 throughout |
| Unchanged native power-history total | 44 | 61 |
| Core RSS range, MiB | 71.13–72.38 | 85.10–91.39 |
| Core RSS first / last, MiB | 71.25 / 72.38 | 85.70 / 90.72 |
| Average CPU, percent of one core | 0.704 | 1.707 |

WSS UUIDs, total persisted session counts, boot IDs and service/Core process start times remained constant across all samples. No session closed. Presence age uses DeviceSession.last_seen_at and remained below the unchanged 90-second threshold. Reset 1 was the pre-existing conservative checkpoint-format migration, not a new log-clear/reset. Power facts were not invented by monitoring or service reconnect.

Linux CPU includes the service cgroup and its children. Windows CPU includes persistent service+Core and excludes short-lived native-reader CPU. The persistent Core was identified separately from private reader processes. Windows RSS increased by about 5 MiB first-to-last but remained below 92 MiB; Linux remained below 73 MiB. These finite measurements do not establish the absence of a slow long-term leak.

## Production observations — read-only, cause not established

The final production read at 2026-10-26T10:24:16Z found 8 fresh sessions and 20 nonretired registrations (7 current agent instances reporting 149, one 127). Missing connections do not establish physical power-off. Across the bounded 24-hour window, persisted records show 9 new sessions and 6 closed/reopened sessions on 4 devices. Every closure audit contains generic `disconnected`; root causes, client faults and telemetry causation remain **UNKNOWN**.

| Anonymous device | Closed/reopened sessions | Close-to-next-session gaps, seconds |
|---|---:|---|
| A | 1 | 103.540 |
| B | 1 | 50.208 |
| C | 3 | 44.807, 32.576, 44.790 |
| D | 1 | 146.741 |

The original five production sessions were unchanged through 15 hours; one subsequently reconnected three times. Server API/worker remained at their original PIDs 243637/243567, with zero restarts and start times on 24 October. One affected instance changed its reported version 121→149 between observations. Instance-version metadata is mutable, so current 149 cannot be retroactively assigned to every earlier session. No matching recent provider OTA-target/report activity was found for these devices; that does not exclude manual/native updates or prove a runtime defect. No production/client restart, update, configuration write or rollout was performed by this test.

These production disconnects prevent any claim that this test established production/fleet stability or resolved those incidents. They do not change the separate uninterrupted 154 test-VM result.

## Cleanup and retained evidence

The Linux/staging observer units `endpoint-stability-24h-20261025` were disabled and removed after successful natural completion. The Windows task `EndpointPowerAcceptance-Stability24h-20261025` was removed after result 0. Their bounded sleep requests ended; startup continuations were removed. Evidence and private backups were retained. Canonical Windows recovery tasks were verified unchanged; quarantined VM123 remained stopped.

Both test agents remained active with the same boot/service/Core identity after cleanup. Endpoint staging API/worker and Helpdesk remained active with original PIDs 130896/130897/119931 and zero restarts. No global power preference changed. The first Linux cleanup wrapper omitted its required label and exited argument parsing before any change; the explicit guarded linux invocation then completed. This cleanup instrumentation error occurred after the test and was not a sampled agent failure.

The same-thread schedule `endpoint-linux-windows-24` was deleted after the bounded test completed, so no additional scheduled checks are intended. The feature branch/worktree and all immutable build artifacts remain available for review; no push/merge or production deployment.

Raw evidence under ignored `output/stability24h-20261025/`: `final-evidence/manifest.json`, three sealed samples.jsonl exports, source status/checkpoint files, `final-analysis.json`, `production-final-analysis.json`, chronological reviews and `production-events-reviewed.jsonl`, plus cleanup receipts. Hashes were checked against their remote originals before analysis.

| Sealed JSONL | Bytes | SHA-256 |
|---|---:|---|
| linux | 4534004 | `97c741f8b7d6652cc44d902cae23f12c2455ab5ec3b848d883ab3d2edd792548` |
| windows | 3552630 | `c7616d8cbe08d9da6e00e892601ad231d252dbfb5755f70e9f5b27c7569b2d82` |
| server | 4429652 | `fe26327b48d14e8d621aa53bba970ac3343cc95f6510b2a3e17648a32f9b609d` |

## Verification executed

```text
PY output/stability24h-20261025/review.py
PY output/stability24h-20261025/production_presence.py
PY output/stability24h-20261025/audit_first_3h.py
PY output/stability24h-20261025/audit_checkpoint.py H   # H=6,9,12,15,18,21,24
PY output/stability24h-20261025/export_final.py
PY output/stability24h-20261025/analyze_final.py
PY output/stability24h-20261025/analyze_production_final.py
git diff --check
```

`PY` is the existing isolated Python 3.12 test environment in this worktree. Per-VM native scripts and the staging read-only SQL observer supplied the raw data. Final analysis validated source identity, all 2881 slots per source, exact timestamps/cadence, service/Core identity and CPU accounting continuity, WSS/session counts, source freshness, queue/counter invariants and all exported digests. Only this new acceptance document is included in the final documentation commit.

## Remaining limits

Thirty-second observations are not a packet trace. This awake-VM run adds no S3, Fast Startup or physical workstation acceptance; prior S3 and immutable 149-rollback limitations remain explicit in the earlier report. Production reconnect causes require separate evidence; this run neither waives those gates nor authorizes fleet rollout.
