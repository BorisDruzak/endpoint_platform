# Telemetry isolation and OS power history

Date: 2026-10-24. Status: approved by the user on 2026-10-24; implementation authorized.

Independent builder review: completed; reviewer reported `nothing important left`.
Preparation checks: `git diff --check` passed. A read-only SSH probe to the dedicated Linux test host `192.168.101.162` timed out on port 22; native power-transition acceptance requires restoring that test host's availability. No implementation tests or power transitions were run during design preparation.

## Intent and scope

Keep an authenticated agent control channel usable when an optional telemetry sample is rejected or a local collector fails. Show OS startup, shutdown, sleep and wake events separately from transport availability so operators can interpret missing connectivity without inventing a shutdown time.

Cover Windows and ALT Linux agents, durable offline delivery, server ingestion, device details/fleet status and the existing activity timeline. Preserve authentication, command validation, updater/recovery behavior, TLS verification and existing DLP policy boundaries. No edits to Helpdesk or web_ovpn are required.

The user requested implementation of both outcomes. The user approved this design and authorized implementation, both native builds, VM acceptance and stability testing. No product code or production state was changed while preparing this document.

## Verified baseline

- Canonical remote/indexed main: `664333249025b41049cf9f9444bdeb7ee403917c`. GitNexus matches that commit. The initial workspace is on `codex/context-device-display-name` at `38ddabe`, 441 commits behind main, with unrelated local changes. Implement from current main in an isolated worktree; preserve all existing changes and other worktrees.
- `endpoint_server/gateway/ws_routes.py:connect_agent` catches `SensorHealthRejected`, `BrowserStatusRejected`, activity `ContextValidationError` and `SecurityEventRejected` outside the receive loop, closing the whole connection as `state_rejected`.
- Production journal on 2026-10-23 at 14:40:45 YEKT recorded `SensorHealthRejected: sensor observation is too old`, matching a durable session close. This is evidence of one actual telemetry-induced disconnect, not an explanation for every historical disconnect.
- Agent `pc_agent/runtime/lifecycle.py:_run_connected` ends the connection when any connected task fails. Optional collectors and transport failures therefore need explicit separation.
- Existing `GatewayErrorV1` handling raises a transport error; `retryable=true` still reconnects. It is not a nonfatal telemetry rejection mechanism.
- Agent reports presence every 30 seconds. Server considers presence fresh for 90 seconds; this proves communication, not power state.
- Existing `device_events` stores compact historical facts with a unique `(device_id, source_key)` and a 2 KiB details bound. Its current `SESSION_ENDED` facts describe interactive sessions, not OS shutdown.
- Existing activity timeline `_connection_gaps` explicitly treats unavailable transport as unknown. Preserve employee activity calculations and their unknown intervals.
- Existing security-event SQLite spool has a 24-hour lifetime and policy-dependent ACK semantics. Power history must not depend on a DLP policy or change those retention rules.

## Approaches

1. **Infer power from last activity or last heartbeat.** Small change, but cannot distinguish a network fault, agent restart, sleep and shutdown. Does not meet the user's intent.
2. **Only send immediate power notifications.** Timely when delivery succeeds, but loses evidence when the network or agent is unavailable during a transition. Insufficient by itself.
3. **Recommended: OS evidence plus durable replay, with separate connection and power projections.** Immediate OS notifications improve timeliness; bounded OS journal recovery fills recoverable gaps after reconnect/startup. The additional protocol/storage work is necessary to avoid false shutdown claims.

Only approach 3 satisfies both reliable history and truthful uncertainty. Proposed implementation uses the existing Python agent/server and React console, extending established patterns rather than introducing a separate service or a DLP event type.

## Telemetry fault boundaries

- Handle validated activity, browser-status, sensor-health and security-event report rejections inside their individual message transaction. Roll back the rejected message, record a bounded reason code/counter, and continue receiving heartbeat/commands on the same session.
- Keep malformed framing, excessive message size, invalid direction, identity/authentication failures, unsupported/unnegotiated message kinds and command-state/protocol violations fatal. Do not broadly catch all server exceptions or treat database/transport failures as successful telemetry ingestion.
- Legacy agents receive no new error frame on an otherwise valid optional report rejection: they interpret existing error frames as fatal. The server records diagnostics without closing their channel.
- Add an explicitly negotiated nonfatal telemetry-result feature for updated peers. Correlate results to report/batch identifiers and return bounded `accepted`, `retry_later` or `rejected` disposition codes. Never send a success ACK for uncommitted or rejected durable events.
- A transient durable-delivery failure leaves the batch pending and backs off. Permanently rejected events are excluded from the hot retry queue, with bounded rejection metadata and loss counters visible to diagnostics; no endless poison-batch replay. Preserve accepted siblings through per-event dispositions or deterministic batch splitting. Do not classify database outages as permanent event failures.
- At the agent, isolate expected collection/projection failures in the owning collector/sender loop, report source degradation and retry with a bounded delay. Preserve cancellation and real transport/authentication error propagation. Do not wrap the entire runtime in a blanket exception suppression loop.
- Slow/failed optional collection must not hold the shared send lock, block the event loop or starve heartbeat delivery. Use the existing bounded background execution pattern for OS reads. Bound log volume for repeatedly rejected reports.

## Power facts and native sources

Introduce a policy-independent `endpoint.power-events.v1` feature and bounded event/batch/ACK contracts. Facts include stable event ID, event kind, occurred time, observed time, boot identity, native source identifier and evidence classification. Device ownership comes from the authenticated connection, never from an untrusted payload override.

Event kinds:

- `OS_STARTED`: native OS boot evidence; restarting/reconnecting the agent on the same boot must not create a new startup fact.
- `OS_SHUTDOWN_STARTED`: OS has begun shutting down. A shutdown request that can still be cancelled remains explicitly a request and cannot establish completed shutdown.
- `OS_SLEEP_STARTED`: OS sleep/hibernate entry evidence, preserving a subtype when the source distinguishes it.
- `OS_RESUMED`: native resume evidence.
- `OS_UNEXPECTED_SHUTDOWN_REPORTED`: the OS reports a previous unclean shutdown at a subsequent startup. Store detection time separately; do not invent an exact power-loss time.

Windows adapter: use native System event-log provider/event identity and power notifications appropriate to the installed service host. Verify the actual `service_launcher.py` ownership/control forwarding before adding hooks; do not assume `SvcShutdown` is the only entrypoint. Distinguish restart, hibernation and Fast Startup from a new full boot. Retain only whitelisted structured fields, no rendered event message, XML, command line or user data.

Linux adapter: use boot identity, logind power transition notifications and authoritative structured journal records where available. Verify ALT/systemd support and service-account journal access in the dedicated test environment. Do not broaden the main agent to root. If additional access is necessary, prefer a narrowly scoped existing-helper extension; make any package/access change explicit in implementation/release notes. Missing journal access or nonpersistent journal yields source-unavailable/coverage-gap diagnostics, never a guessed event.

Exact native API/event mapping is an implementation responsibility and must be verified against official version-appropriate OS documentation and real captured metadata before the adapter is accepted. Adapters must distinguish a request from transition evidence and survive journal reset, rollover and clock changes.

## Persistence and delivery

- Store power facts in an independently bounded durable SQLite queue under the protected agent data root, using the existing safe-file and transaction conventions. Keep OS cursor checkpoints there as well.
- Proposed bounds: 30 days, 10,000 events, 5 MiB serialized payload; oldest-first eviction with persistent counters. Bound each batch to 128 events and 60 KiB, and each metadata object below the server's 2 KiB limit.
- Commit an event locally before advancing its OS journal checkpoint. Recover from an invalid/reset cursor with bounded replay and stable native event identifiers. Avoid duplicate startup events on agent restarts.
- On connection, send only after the server explicitly advertises support. Add optional server-supported protocol features to the hello contract and regenerate JSON schemas/fixtures. Deploy the provider before agents advertising new enum values; old servers currently validate feature enums strictly.
- Server ACK follows durable commit and includes exact event identifiers. Retries are idempotent; a repeated ID with conflicting contents is a permanent rejection, not an overwrite. Crash between commit and ACK must produce one historical event after replay.
- Accept historical power events up to the dedicated 30-day horizon without changing the 24-hour DLP/activity bounds. Record ingestion time separately. Excess future skew, expired events, unavailable native timestamps and resets produce explicit diagnostics. Late/reordered history must never roll the current projection backward.
- Reuse `device_events` for compact accepted power history (`category=power`, `profile=power_v1`), with deterministic source keys and validated bounded metadata. Prefer deriving the latest power evidence from those indexed rows; add a migration only for genuinely necessary indexed projection/support fields, with a single migration head and tested PostgreSQL upgrade.
- Preserve existing context-event history and retention behavior. A dedicated maintenance rule retains power facts for 30 days and exposes the earliest available coverage boundary; this is operational history rather than indefinite audit retention.

## Operator-visible behavior

Represent connectivity and last power evidence separately; activity remains a third, independent signal.

| Evidence | Display and meaning |
| --- | --- |
| Fresh authenticated presence | `В сети`; show latest power event as historical information |
| Connection lost, no applicable OS power evidence | `Нет связи — причина неизвестна`; show last connection and last user activity separately |
| Native sleep entry followed by missing presence | `Последнее событие: переход в сон`; show source/time; do not present a user logoff as sleep |
| Native shutdown entry followed by missing presence | `Последнее событие: завершение работы ОС`; do not claim the hardware is physically powered off |
| Startup/resume received later | Add its actual event time to history and end the relevant historical power interval where evidence allows |
| Source unsupported/unavailable or history expired | Explicit coverage/availability note; unknown gaps stay unknown |

Fresh presence always wins over an old shutdown/sleep hint. Delayed facts never override newer startup/resume/current communication. Evidence from a cancelled shutdown request is not used to label an offline interval as shutdown. A later silent network failure cannot inherit a historical sleep/shutdown label after subsequent known communication. Use event time and boot/source ordering rather than receipt order.

Add power evidence and separate timestamps to fleet/device detail projections and Russian UI labels. Render power history in the existing device event list and markers/interval evidence alongside activity connection gaps. Keep `online` backward compatible. Do not count lack of connectivity as employee inactivity or time powered off.

Physical power state cannot be proved after sudden power loss while the machine cannot communicate. The product explicitly retains uncertainty until OS evidence arrives, possibly on the next boot. Exact historic recovery is also limited by OS log retention.

## Compatibility and verification

Extend canonical contracts/schema generators and relevant OpenAPI responses at their source. Existing external HTTP consumers keep their current routes/field semantics; validate affected provider contracts and use GitNexus group status/impact if cross-repository exposure is changed. No manual managed-link edits or group synchronization.

Required acceptance cases:

1. Rejected stale/future/policy-mismatched optional reports leave the same authenticated session usable for a later heartbeat and command. Rejection has no partial writes and no success ACK.
2. Local collector failure/deadline or unavailable power source does not stop heartbeat/commands. Authentication, malformed framing and true transport failures retain their existing behavior.
3. Durable replay, duplicate/conflicting identifiers, mixed valid/rejected batches, ACK loss, restart during persistence, queue overflow/expiry and invalid cursor recovery have observable bounded outcomes.
4. Windows and Linux parsing uses realistic native metadata fixtures, including shutdown request cancellation, Fast Startup/hibernate, journal rollover and unclean shutdown detection.
5. Agent restart on the same OS boot adds no `OS_STARTED`. Boot/resume following offline events restores chronological history; old events cannot change current state.
6. Network loss with no OS evidence remains unknown; user lock/logoff/session end never means computer shutdown.
7. Old agents/new server and updated agent/server combinations remain compatible; new agent/old server is gated by provider-first upgrade and negotiated support.
8. Test migrations on PostgreSQL when required, contract/schema consistency, affected server and agent suites, frontend tests/typecheck/build, and browser rendering of the new labels/timeline.
9. Use the dedicated nonproduction Linux host for actual sleep/resume/reboot/service-restart tests and a designated Windows test VM for Windows transitions. Do not reboot, suspend or shut down an employee workstation for acceptance.

Implement and verify in reviewable commits. Report implemented behavior, exact commands/results, native tests actually performed and any unverified cases separately. Production publication, agent release packages and fleet rollout follow their normal release gates; no claim of live deployment without actual deployment and verification.

## Decisions left to implementation

Module names and focused helper boundaries; exact native collectors after documented API/version verification; whether a separate current-state table is justified; small Russian layout changes fitting the existing console. No new framework, telemetry backend or global DLP-policy switch is required.
