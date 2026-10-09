# Task 13: resume gate verification

Client date: 2026-10-10. Product baseline:
`5d36fd383328cba10d2d3f6b55fe2e8489b8fb31`.
Committed diagnostic implementation:
`86b8846d2e18677b4618e23841fd273ad5e62cf5`.
Decision: **BLOCKED**. Saved recovery progress remains **UNKNOWN, 4/12**.

This verifies the requested resume gate after the
[performance isolation](2026-10-09-task-13-comparator-performance.md).
Only fresh read-only infrastructure/provider queries and local validation ran.
No comparator, marker, VM stop/start, snapshot creation, rollback, installation,
service operation, provider mutation or release-byte change was dispatched.

## Canonical execution path: blocked

The immutable canonical FixedAdapter.guest still loads the original sealed
Invoke-Task13RecoveryGuest.draft.ps1, SHA256
`cb5a2266adb77783f9ce4802505da9b3a8553d88511d48c85f3dbc5f1ed76aaa`,
builds its guest transport and calls the original bounded-process transport.
It does not link the new Get-Task13MsiTables reader or the independently scheduled
Watch-Task13DiagnosticProcess watchdog. Those corrections were exercised by a
separate sealed diagnostic package. Their successful run is not receipt 04.

The canonical plan expired at **2026-10-09T07:05:28.618169Z**. Its live_plan
requires the original UTC interval, original absolute monotonic deadline and
exactly 1,200 seconds of duration. verify_chain begins with live_plan, and
next_step uses verify_chain. Direct local calls to all three functions refused
the saved run with `run expired or duration changed`; no time override was used.

The runner starts with receipts empty and a new capture; it has no continuation
loader for checkpoint 03. Changing old deadlines or helper pins changes the
plan/seal digest and invalidates the four receipts. Also, guest Facts includes
the original run_id and plan_sha256, and the protected comparator checks the
entire serialized Facts against baseline. Passing a fresh plan digest to that
guest would break the baseline comparison. Omitting those fields is not valid.

## Fresh state reconciliation

All hypervisor observation commands returned exit 0. VM running state, saved
configuration, selected snapshot metadata and intrinsic snapshot-volume
identities matched the retained snapshot receipt. Active hypervisor tasks were
empty. Compared with the previous diagnostic postflight:

| Boundary | Fresh observation |
|---|---|
| VM/checkpoint | Same boot and baseline bytes/hash; marker absent |
| Snapshot | Retained configuration, metadata and volume identities match |
| SCM | Agent Running/Automatic; Updater and msiserver Stopped/Manual; process IDs unchanged |
| Windows Installer | No msiexec; checked InProgress, Rollback/Scripts and reboot-pending keys absent |
| Update state | Installer fence, pending update, startup attempt and terminal outcome absent; history/report/startup-confirmation hashes unchanged |
| Endpoint provider | Migration 0037_launcher_foundation; Agent/Launcher 3.2.81; instance last-seen age 19.015863 seconds; one matching authenticated fresh session |
| Update ownership | Zero active device owners and zero visible recommendations |

The provider observation came from the sealed provider query in a read-only
PostgreSQL transaction with a statement timeout and rollback. No pause, resume,
assignment or deployment request occurred. The query's rollout_targets field
is empty by its unselected-rollout filter; it is not an inventory of all rollouts.
The active-owner predicate was checked against the committed update service:
assigned, requested and scheduled are its active target statuses.
These observations verify state at the recorded query times; provider/session
freshness must be rechecked before any later dispatch. They do not revive the
old plan.
The initial provider record is a transport candidate. A second read-only query
retained raw stdout/stderr before parsing and confirmed the same ownership and
versions; its candidate byte counts and parsed JSON were checked against those
bytes and recorded hashes. Neither observation is a canonical accepted recovery
receipt, and neither may be promoted into one. Future dispatch requires fresh
checks at use time.

## Four checkpoints: historical integrity confirmed

Independent review verified the original ordered prefix:
capture, stop-for-snapshot, snapshot, start-after-snapshot. Predecessor links,
run seal, baseline, original chronology, source pins, transport digests and
accepted observations match. The absence of a completed compare-after-start
receipt was preserved. Historical integrity is separate from live authorization.

| Anchor | Canonical SHA256 |
|---|---|
| Plan | bbddf13f084c6be9c7fed8fc2041df88953aabb33915ce12631eeab0f1c7fa5d |
| Run seal | 6f30d2b3698498f4daa55aa2a8f1fd6e4181e3a20498c8ce8a7de4da37d74590 |
| Receipt 03 / chain tip | cdd42d87efa105f78957240838b96e0232784869d36f5335396aa341168cf4fd |
| Baseline bytes | cdbdf079698747b2af32e7749291388099f04275e10c13995616c8d1206e1534 |
| Snapshot identity | 923000023d7996498bd6ce51b822a171e626c04335c9403cd2e1f7d1e59074d5 |

## Requested transitions

| Requested step | Result |
|---|---|
| Corrected comparator/watchdog in canonical chain | FAIL: canonical source closure still binds original helper/transport |
| Fresh VM/hypervisor/snapshot/MSI/SCM/provider/update-state | PASS for recorded read-only reconciliation |
| Independent four-checkpoint verification | PASS for historical integrity; no live authorization |
| Canonical compare-after-start and genuine receipt 04 | NOT RUN: expired execution plan and missing continuation support |
| marker, compare-before-restore, stop/restore/start, restored, provider-after-restore | NOT RUN: required preceding canonical PASS absent |

No recovery receipt was synthesized, promoted from diagnostic evidence, appended
or overwritten. The old plan, seal, four receipts and baseline remain immutable.

## Required continuation contract

The next implementation must introduce an additive, independently reviewed
continuation protocol. It must bind the original plan/seal, all four receipts,
tip, baseline and snapshot while keeping their bytes unchanged. A distinct
fresh execution identity must seal its own UTC/monotonic deadlines, source
closure and exact comparator, watchdog, wrapper and wire hashes. The original
capsule RunId/PlanSha256 must remain in the guest's unchanged baseline projection.

The loader must verify checkpoint 03 and allow only seq 4 compare-after-start
next. The receipt validator must explicitly support the new amendment identity
and evidence bindings, rather than weakening the old validator or renewing old
timestamps. COMPLETE must require fresh ownership/runtime and clock gates,
native retained-handle exit, protected diagnostics, inventory and settlement.
Otherwise the outcome remains UNKNOWN with no next dispatch.

Only after that protocol's source/control review and a genuine canonical receipt
04 PASS may marker and later transitions proceed, with separate checks at each
boundary. A rollback still requires the canonical stop-for-restore, verified
rollback settlement, start-after-restore, restored comparator and fresh provider
observation; those steps cannot be collapsed into a single rollback command.

## Review and publication boundary

GitNexus was queried for the committed architectural baseline; the private
canonical closure was verified directly against its sealed source and records.
The original predicates were executed locally to confirm refusal, without
monkeypatching clocks or liveness. No harness or runtime implementation changed
in this verification. Runtime change required: **not established**; none made.
Independent checkpoint and gate reviews are retained in protected evidence,
alongside current raw observations and exact hashes. Private topology, identities,
commands and credentials are excluded from Git.

Independent checkpoint-review SHA256:
`373b5ad1dbf9f5e0104592834f4c74b080259713bd2c4e6b3f96023f3c6420a0`.
Independent gate-review SHA256:
`dd2f05fa45171bc9212eb140abf82f6d535875ec173f75a62a3414431ae29a96`.
These reviews confirm evidence integrity and the BLOCKED decision; they do not
authorize execution. The later raw-provider retention supplement and publication
review are stored separately.

This report records a failed resume gate, not READY FOR FLEET. Task 13 remains
**BLOCKED, UNKNOWN 4/12**. Mass rollout remains prohibited.
