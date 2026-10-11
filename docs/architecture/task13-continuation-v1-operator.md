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
tests/tools/test_task13_msi_profile.py tests/tools/test_task13_watchdog.py -q`.
For the retained historical evidence cases, supply the private
`TASK13_HISTORICAL_ROOT` environment input. Test fixtures and owned local
processes do not produce operational authority or actual VM acceptance.

Native design references: [CreateFile sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[non-replacing handle rename](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info),
and [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
