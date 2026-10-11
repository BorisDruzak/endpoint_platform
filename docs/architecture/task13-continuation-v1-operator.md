# Task 13 continuation v1 operator boundary

This additive local controller authorizes only seq 04, compare-after-start.
Agent, MSI, Setup, provider runtime and original receipts remain unchanged.
The public `tools/canary/run_task13_continuation.py` entry always refuses.

## Preparation and independent review

Use Python 3.12 and an elevated Windows controller. `prepare_bundle` creates
a fresh SYSTEM/Administrators directory, verifies the retained original
checkpoint and generates a separate compare-only helper. It performs no
network or VM operation. Private targets, original helper bodies, library
paths, observer inputs and operator-session records stay outside Git.

The bundle contains immutable execution bytes and a closure manifest covering
Python modules, scripts, reader/profile/watchdog, compressed entries, wrapper,
wire, original bindings, both interpreter/library implementations and strict
SSH host-key input. Controller and management child disable bytecode writes
and select an empty bundle cache prefix. Both execute with `-I -S -B`;
the management child adds only its explicitly pinned Paramiko library roots.
Unrelated installed packages and site startup hooks are not executed.

An independent reviewer must inspect the exact closure and control inputs.
The reviewer writes canonical `review.json` and detached `trust.json` into
the prepared protected root using native exclusive writes. Review status must
be PASS, and its scope must match `authority.REVIEW_SCOPE`. Detached trust
pins the closure, review, bootstrap and actual operator-message artifact and
records the reviewer's kernel-observed process identity. The creator process
must differ. Changes require a new exact-source review before VM contact.
The loader accepts no caller-selected adapter or review-file path.

These local trust slots belong to the trusted elevated operator/reviewer
boundary. They do not protect against a malicious administrator who replaces
the controller, its trust slots or the Codex app session. Caller-supplied
JSON, quotation or receipt status does not create operational permission.
Permission is reconciled with the latest real user message in this app session.

## Canonical execution

Run only the protected bundle's `bootstrap.py` with the explicit
`--execute-reviewed-seq04` flag and isolated Python. The loader retains source
and directory handles, validates exact hashes and the original prefix, observes
actual host/boot/process/token identity, then creates fresh 1,200-second
UTC/monotonic authority and creator attestation. Original live predicates still
refuse the expired original run.

Fresh read-only preflight covers VM status/config/generation, intrinsic
snapshot and LVM identities, active tasks, provider ownership and authenticated
3.2.81 runtime/session freshness, SCM/MSI/update quiescence, baseline leaves,
old wrapper quiescence and guest/management clock brackets. A permanent
exclusive claim in the reviewed original checkpoint's canonical claim home
then reserves original seq 04 across continuation IDs and process restarts.

Only after that claim does the loader prepare a fresh protected guest evidence
root and independent SYSTEM watchdog. The workload publishes its actual birth
identity and waits for a retained-handle arm before native comparator work.
Workload ceiling is 120 seconds, settlement 10 seconds, SSH observation 145
seconds, with two seconds reserved for persistence. Source-bounded compressed
entries avoid the Windows command-line size ceiling.
State is reconciled again after preparation; its clock/owner predicates run
after durable intent persistence immediately before comparator process creation.
After that validation, the loader rechecks the full operation plus persistence
reserve and applies a pre-parsed, I/O-free freshness check at the actual dispatch
timestamp. Receipt validation repeats preflight predicates at that timestamp.

SSH stderr/nonzero, incomplete input, timeout, source drift, failed predicate,
unconfirmed/terminated native exit or incomplete journal produce refusal or
UNKNOWN. A consumed claim is never removed and no retry or compensation runs.
The normal path retains raw transports, journal, process identity, watchdog
records and fresh postflight; it validates the actual comparator output and
original Facts identity before publishing only a new receipt 04.

## Publication and stop

Canonical continuation receipt and evidence live in the protected bundle
root, linked to the immutable original receipt-03 tip. Historical records are
not edited to insert the continuation. Publication uses a staged flushed file
and native non-replacing handle rename. File-system metadata is flushed through
the local NTFS volume handle; this can add local disk I/O latency. Uncertainty
does not authorize another dispatch. A complete-looking receipt without the
separate durable publication candidate in `resume-gate.json` is not
accepted by the continuation receipt verifier. Even those two records cannot
open the gate by themselves: a reviewed local supervisor retains the actual
root process kernel handle and records its normal exit 0, PID/birth, raw streams
and observed completion clocks after the root's final authorization check.
`root-completion.json` must bind that observation to the exact capsule, receipt,
evidence and publication bytes within the root authority window. The supervisor
performs no target operation; persistence of this local exit witness follows
the already durable authorized root publication. `unknown.json` or
`supervisor-unknown.json` takes precedence in the canonical persisted verifier.
Crashes, expired finalization and missing witnesses leave the gate blocked.

The receipt's resume gate is `STOP_BEFORE_SEQ05`. Marker, restore, seq 05–09,
Agent/installer tests and mass rollout require separately authorized work.
A canonical receipt 04 is not Task 13 completion or fleet readiness.

## Local verification

In PowerShell, run `python -B -m pytest (Get-ChildItem
tests/tools/test_task13_continuation_*.py).FullName
tests/tools/test_task13_process_identity.py tests/tools/test_task13_msi_profile.py tests/tools/test_task13_watchdog.py -q`.
For the retained historical evidence cases, supply the private
`TASK13_HISTORICAL_ROOT` environment input. Test fixtures and owned local
processes do not produce operational authority or actual VM acceptance.

Native design references: [CreateFile sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[non-replacing handle rename](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info),
and [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

## Recovery after initial preflight UNKNOWN

Use the separately reviewed procedure in
`docs/superpowers/specs/2026-10-11-task-13-unknown-recovery-design.md`.
Fresh bundles now require the fixed failed attempt's protected evidence and the
actual recovery authorization. Offline preparation verifies that the actual
capsule creator has terminated; a Windows venv launcher's exit alone is insufficient.

The repeat uses a pinned direct base interpreter and a permanent recovery-launch
claim shared across continuation IDs, consumed before root creation. It also retains
the existing original seq04 dispatch claim. Neither claim may be removed to retry.
Any later UNKNOWN requires another explicitly authorized recovery procedure.

Source review PASS and recovery admission are separate from runtime reconciliation.
The PID Identity Guard Correction replaces only known/pair numeric absence with
instance admission. A stable native instance created after the pinned historical
absence witness is `PID_REUSED`; two consistent native/CIM absence samples are
`PROCESS_ABSENT`. A saved original birth still alive is `ORIGINAL_PROCESS_ACTIVE`.
Missing identity, access denial, unexplained chronology or an exit/restart race is
`IDENTITY_UNKNOWN`. The latter two states block continuation. Native birth equality
retains all 100 ns ticks; CIM comparison uses its exact microsecond projection.
Original leaf/marker absence, wrapper scans and all other predicates remain sealed.

Prepare and independently review a fresh exact bundle, then invoke its pinned base
interpreter with `-I -S -B` and `bootstrap.py --observe-reviewed-guard`. This fixed
entry records eight read-only constituents and a fresh bounded observation window
under `read-only-guard/`. It creates no execution capsule, launch/workload claim,
watchdog or receipt. Its permission scope rejects both seq04 execution flags before
execution mutations. `READY_FOR_SEPARATE_SEQ04` is observation readiness only;
seq04 remains a separate reviewed execution step. Do not interfere with `sshd.exe`.
`STOP_BEFORE_SEQ05` acceptance requires the real receipt and root completion.

For the already authorized separate step, `prepare_bundle(..., separate_seq04=True)`
requires the fixed prior full-gate admission. The new request scope binds its digest
and the actual human message. The reviewed loader retains all eight admission
artifacts and revalidates the original binding before any root claim. The correction
package remains immutable and cannot execute seq04. Independently review the new
exact execution package before invoking its seq04 supervisor; its fresh canonical
preflights, deadlines, watchdog and permanent claims still govern dispatch. A later
UNKNOWN must not be retried by removing claims or borrowing the prior READY record.

Identity design references: [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
[CIM datetime precision](https://learn.microsoft.com/en-us/windows/win32/wmisdk/cim-datetime),
and [Win32_Process parent identity](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process).

## Read-only recovery with historical RCA UNKNOWN

The subsequent actual human request authorizes a new observation scope while
explicitly retaining the old RCA as UNKNOWN. Prepare with
`prepare_bundle(..., readonly_recovery=True)`, obtain independent exact-package
review PASS, then invoke the pinned base interpreter with `-I -S -B` and
`bootstrap.py --observe-reviewed-guard` once. This scope rejects both execution
entries and permission upgrades before execution mutations. It cannot be combined
with `separate_seq04=True`.

The recovery record pins and retains the failed attempt, its historical UNKNOWN,
and its consumed launch claim. The claim is read as immutable evidence; it is
neither removed nor reused. All original history, source/runtime pins, native
identity requirements, eight canonical constituents and bounded deadlines remain
mandatory. An UNKNOWN stops this observation; it supplies no repeat authority.

Native identity v2 adds bounded stage, immediate Win32 error, partial sample,
ErrorRecord/exception-chain and caller-context diagnostics. Original identity rows
and classification remain unchanged. API failures and incomplete/racing instances
remain UNKNOWN even when a partial birth is available. No command lines, invocation
text, TargetObject or unrestricted exception messages are recorded. Raw identity
and security-context evidence stays in protected local storage.

Successful reconciliation is `READ_ONLY_CANONICAL_PREFLIGHT_PASS`, with
`historical_rca=UNKNOWN`, `seq04_authorized=false` and the consumed-claim preservation
result. It creates no execution capsule, launch/workload claim, watchdog or receipt.
This result authorizes no seq04 dispatch. Do not interfere with `sshd.exe`.

## One separately authorized execution after read-only recovery

The subsequent actual human execution request creates a distinct
`seq04-after-readonly-recovery` scope. Prepare with
`prepare_bundle(..., separate_seq04=True)` and obtain independent exact-package
review PASS before invocation. The fixed successful read-only recovery and its
independent audit are admission evidence; they never replace a fresh preflight.
The read-only package remains unable to execute under the new request.

The original expired execution capsule is not extended or reused. The new actual
child creates a new native-controller1200-second capsule. Its source/runtime pins,
eight canonical constituents, clocks, watchdog, immediate dispatch freshness and
receipt/root settlement predicates are unchanged. The unchanged original global
seq04 claim is still required before workload dispatch.

A new permanent execution launch claim is keyed by the original seal/tip, the
full actual authorization record and fixed recovery admission. The key does not
depend on CID. CREATE_NEW occurs before Popen; the child retains the claim and
matches request, CID and exact closure owner. Repeated same-owner/new-CID launches,
spawn failure and UNKNOWN cannot restore or reuse this claim. The old consumed
recovery claim and historical UNKNOWN remain immutable evidence.

Invoke only the reviewed pinned base interpreter with `-I -S -B` and
`bootstrap.py --execute-reviewed-seq04`. Success requires genuine comparator PASS,
canonical receipt04, root normal exit and independent offline receipt audit.
Then STOP_BEFORE_SEQ05. Marker and restore are outside this scope. Any failure
stops without another launch or synthesized receipt.
