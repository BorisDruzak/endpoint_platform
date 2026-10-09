# Task 13: comparator performance isolation

Date: 2026-10-09. Product baseline:
`5d36fd383328cba10d2d3f6b55fe2e8489b8fb31`.
Implementation starts from main `7411ef5f16653d81d924da688a52c51fd2807248`.
This is a narrow diagnostic supplement to the
[previous controlled comparison](2026-10-09-task-13-controlled-compare.md).
It does not resume Task 13 or authorize fleet rollout.

## Watchdog validation on the dedicated VM

Portable Python 3.12.10 was placed under a fresh protected diagnostic directory.
The [official Windows embeddable archive](https://www.python.org/downloads/release/python-31210/)
matched its published MD5; transport SHA256 and a valid Python Software Foundation
Authenticode signature were verified. No system Python installation, registry,
global PATH, Agent or Setup change was made.

All ten synthetic watchdog cases actually ran on the VM with Python 3.12.10:
sleep, stdin wait, normal return, capture stall, capture write failure, missing,
empty and oversized journal, wrong run and wrong birth identity. No case skipped.
Forced cases used a three-second ceiling. The latest observed termination request
was at 2.514875 seconds from native process birth. Every accepted target exit was
confirmed through its retained native handle. Valid journal capture completed
before forced termination with zero target stdout; failed/stalled captures were
explicitly incomplete. Identity mismatches were refused without killing targets.
Owned synthetic children were reaped by the test driver.

This verifies the corrected watchdog from main, including its 500 ms internal
margin. It measures termination-request timing, not a stronger guarantee about
Windows scheduling or the exact instant of process exit.

## Synthetic logging benchmark

Three bounded trials per mode ran on the same VM. Each performed 2,000 identical
native synthetic operations representing 4,000 logical ENTER/RETURN events.
Serialization happened before timing; streams were opened before timing, and
both matched-byte modes used the same buffering/file options. Timed disposal
and the final flush were common to all modes. Trial order was reversed once.

| Mode | Durable flushes per trial | Bytes | Median ms |
|---|---:|---:|---:|
| Flush(true) after every event, plus final flush | 4,001 | 154,000 | 2,352.7175 |
| Same complete event stream; flush every 128 operations, plus final flush | 16 | 154,000 | 40.8396 |
| Aggregate counters and one final durable summary | 1 | 44 | 6.3380 |

The first two modes produced identical file hashes and event counts in every
trial: changing flush frequency alone reduced the measured time by 57.61 times.
The counter-only mode also reduces emitted bytes and work; its 371.21-times
ratio against per-event flushing is not an isolated measurement of flush cost.
These are synthetic local I/O results, not proof of the historical hang's cause
or a prediction of fleet performance. The earlier per-call diagnostic logger
also opened/closed streams, serialized frames and used WriteThrough per event;
those additional costs were intentionally excluded from the matched-byte test.

The generic benchmark tool requires a protected SYSTEM/Administrators-owned
output directory, rejects reparse ancestors and uses CreateNew output files.
The executed VM benchmark's sealed source and records remain in private evidence;
the published tool adds these reusable directory checks and an explicit Root.

## Bounded MSI_TABLES reader

Five fixed tables are read through one read-only database connection, one view
and one Execute per table. Each record is fetched once; FieldCount is cached
once per record and each field is read once. There is no metrics rescan.
Length-prefixed full-row keys detect duplicate records without logging values.
The original value conversion, case-sensitive sorting and comparator remain.

Each table has OPEN, EXECUTE, ROWS, SORT and CLOSE marks and a final summary.
Rows are divided into at most 128-record chunks. Bounds are 6,000 rows per table,
64 fields per row, 20 seconds per table and five seconds per row chunk.
Cooperative checks cannot interrupt an in-flight COM call; the independent
120-second native watchdog remains the hard external control. CLOSE is attempted
in finally. These limits do not imply an individual COM call has a timeout.

Other instrumented native sites retain caller scope and ref/return semantics,
but collect timings/counts in memory and emit summaries at durable phase
boundaries. Unreturned calls are explicitly UNKNOWN. A forced stop can lose the
current aggregate and identify only the last durable phase/chunk, rather than
the exact last native method. No incomplete aggregate is reconstructed.

## Exactly one controlled comparison

Independent source/control review passed before dispatch. Fresh preflight
reconciled the retained baseline, VM configuration, snapshot metadata and
intrinsic snapshot-volume identities. The existing pre-scenario snapshot was
reused: no new snapshot, restore, reboot, install or service operation occurred.
The controller consumed a fresh one-shot guard and performed no retry.

The comparator returned **GUEST_COMPARATOR_PASS**, SSH exit 0, in
**90.475216 seconds**, with 3,551 stdout bytes and zero stderr. The protected
baseline comparison was unchanged and passed byte-for-byte. The watchdog
confirmed normal exit 0 through its retained handle; no forced termination
was needed. The protected journal contains 672 frames / 152,395 bytes, including
35 native profile summaries and no unfinished-profile mark.

| Table | Rows | Fields | Fetch calls, including EOF | FieldCount calls | Row chunks | Table ms |
|---|---:|---:|---:|---:|---:|---:|
| Component | 2,558 | 15,348 | 2,559 | 2,558 | 20 | 18,470 |
| Feature | 1 | 8 | 2 | 1 | 1 | 48 |
| FeatureComponents | 2,558 | 5,116 | 2,559 | 2,558 | 20 | 16,966 |
| ServiceInstall | 3 | 39 | 4 | 3 | 1 | 60 |
| ServiceControl | 3 | 18 | 4 | 3 | 1 | 45 |
| Total | 5,123 | 20,529 | 5,128 | 5,123 | 43 | 35,622 overall |

There were exactly five views and five executions; duplicate count was zero.
The maximum completed row-chunk time was 967 ms, below its five-second bound.
The old loop would invoke FieldCount once per field plus its terminal condition:
25,652 calls for these same rows, versus 5,123 now. This avoided 20,529 redundant
metadata calls; fields and records were not skipped. The longest completed
table consumed 18.47 of its 20 seconds: success on this run does not establish
large timing headroom under other VM loads.

Postflight and settlement confirmed comparator, parent and watchdog absent,
scheduled task idle with result 0, and journal restricted to SYSTEM/Administrators.
Before/after SCM state, process IDs, baseline bytes/hash, marker absence, boot,
update-state hashes, snapshot configuration/metadata/volumes were unchanged.
Agent remained Running/Automatic; Updater and msiserver remained Stopped/Manual.
No msiexec process, checked Installer InProgress/Rollback/reboot-pending key,
installer fence, pending update, startup attempt or terminal outcome appeared.

## Verification and decision

RED: four new reader tests failed before the reader existed. GREEN: ten final
reader/profile cases passed locally and on VM Python 3.12.10, including exact
reference-output equivalence for empty, single and chunk-boundary records,
duplicate/row/field/time refusal, view closure, native ref/false return semantics
and incomplete aggregates. A full packet under Restricted process policy passed
stdin/decode/ScriptBlock creation and refused the wrong machine.

Local command:

```text
python -m pytest tests/tools/test_task13_watchdog.py tests/tools/test_task13_msi_profile.py tests/tools/test_canary_fingerprint_probe.py tests/packaging/test_windows_canary_wrapper_contract.py -q
```

Result: **31 passed**. Separately, VM Python 3.12.10 executed ten watchdog cases
and ten reader/profile cases, all PASS without skips. PowerShell parse checks
and git diff --check passed. This is not a CI or Agent 3.2.82 acceptance claim.

Independent source/control review: **PASS**, SHA256
`877095a4bb2c6c1d4d89d8863c4e20f7fb4f21c28e9e7a42975eebb58d669ba6`.
Independent actual-result review: **PASS**, SHA256
`53352be5899ab7142ce58c4be79200f01ee374b5cc075b716ad912aaae296301`.
Publication review is retained separately in protected evidence.

The narrow performance isolation and one comparator completed successfully.
Runtime change: **NO for this change**; published Agent/Setup/MSI 3.2.82 bytes
were not modified. A bounded diagnostic workaround has been demonstrated for
this comparator. The original PID 5228 cause remains unestablished; acceleration
of a later instrumented comparison is not historical RCA proof.

Overall Task 13: **BLOCKED**, saved **UNKNOWN, 4/12** unchanged. This read-only
recovery comparator does not satisfy the remaining Agent 3.2.82 acceptance
scenarios, server-operation reconciliation or the full resume gate.
Mass rollout remains prohibited until **READY FOR FLEET**.

GitNexus was consulted for the indexed committed harness baseline. Source search
verified that the new readers/profilers are diagnostic tooling used by synthetic
tests, with no Agent runtime, provider API or cross-repository contract changes.
Raw VM identity, commands, input bindings and journals remain protected outside Git.
