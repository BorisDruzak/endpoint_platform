# Task 13 continuation: initial local audit

Date: 2026-10-11. Requested committed baseline:
`9144a26472239e5a4c61a79aacdabbda4ec961bc`.
Fetched origin/main and the GitNexus endpoint_platform index both match it.
The current checkout is a different branch, at
`38ddabe3c0badf09a033bb7523a89a7d2c5059a0`, with an unrelated pre-existing
untracked specification. Implementation must use the requested baseline.

This report records read-only local inspection and validation. No remote command,
VM operation, new authorization, comparator execution or receipt publication ran.
No runtime, original sealed helper, plan, seal, receipt or baseline was edited.

## Actual ownership of checks

- `task13_recovery_controller.draft.py:live_plan` owns original run identity,
  fixed 1,200-second UTC interval and local absolute monotonic liveness.
- `verify_chain` calls `live_plan` before checking sequence, predecessors,
  baseline, chronology, snapshot configuration/creation bookends, LVM topology
  and VM generation. `next_step` calls `verify_chain` and enforces order.
- `FixedAdapter.guest` supplies original RunId and canonical PlanSha256,
  loads the original pinned guest helper, creates the exact-count guest wire
  and wrapper, and persists source/wire/wrapper dispatch bindings.
- `FixedAdapter.call` independently calls the original `live_plan`, checks
  fresh clock brackets, uses bounded transport, retains candidate outcomes,
  validates supervisor acceptance and persists accepted observations.
- Guest `Facts` includes original run_id and plan_sha256. The comparator hashes
  baseline bytes and compares the complete serialized Facts projection.
- The runner starts with an empty receipt list and seals a new capture. It
  has no checkpoint-03 loader and normally iterates the twelve-step sequence.
- The corrected diagnostic generator replaces NativeRows with the fixed MSI
  reader and adds aggregate instrumentation. Its execution package remains
  separate from canonical recovery execution.
- The external watchdog opens and retains an exact process handle, checks birth,
  and records wait/exit settlement. Its existing Limit=120 controls the workload
  budget; final native exit confirmation can take a further ten seconds. A new
  supervisor must budget this settlement explicitly and must not accept a
  timeout or merely returned SSH invocation as normal comparator completion.

## Locally verified historical structure

The original module was imported without modifying its functions or clocks.
Direct calls to live_plan, verify_chain and next_step each raised
`run expired or duration changed`.

A separate read-only audit checked raw file hashes, canonical plan/seal hashes,
seal-to-plan equality, exactly four ordered COMPLETE receipts, predecessor
links, original UTC/monotonic chronology, snapshot creation/configuration
identity, PRE_ROLLBACK LVM topology, unchanged VM generation and all original
helper source pins. Before/after raw hashes were identical. This is historical
structure verification; full retained transport/source-closure validation and
fresh guest baseline/provider/VM observations remain prerequisites for execution.

| Object | SHA256 |
|---|---|
| Original plan | bbddf13f084c6be9c7fed8fc2041df88953aabb33915ce12631eeab0f1c7fa5d |
| Original run seal | 6f30d2b3698498f4daa55aa2a8f1fd6e4181e3a20498c8ce8a7de4da37d74590 |
| Receipt 00 | cfee02365b325be914625d0e17155d2dcf50707158f21fc571516fc83c0f579c |
| Receipt 01 | 3dfa3995369e4c2052de8d8f6f4dee878fe3596fccb386e9af758e6c641c57ed |
| Receipt 02 | bab49be079688046908ae66c8e4ff0b75260b7fe3d10f11c76ca2243640ca5cb |
| Receipt 03 / tip | cdd42d87efa105f78957240838b96e0232784869d36f5335396aa341168cf4fd |
| Baseline anchor in seal | cdbdf079698747b2af32e7749291388099f04275e10c13995616c8d1206e1534 |
| Snapshot identity | 923000023d7996498bd6ce51b822a171e626c04335c9403cd2e1f7d1e59074d5 |

The guest baseline bytes were not fetched in this turn; the seal anchor alone
does not establish current guest baseline equality. No canonical receipt 04
exists in the original records directory.

## Corrected committed source candidates

These bytes were hashed from the clean main checkout at the requested baseline.

| File | SHA256 |
|---|---|
| Get-Task13MsiTables.ps1 | 13c5a93944ee4b4386e3f81f2dcf0cdde020864949b7b480f3e15d55af73d3fc |
| Task13AggregateProfile.ps1 | 0221009b6857f633c4117e65bfd6d1d02bea3079ca20717f5777d9e3a41422b4 |
| Watch-Task13DiagnosticProcess.ps1 | b5d547a1b5d865ff7f3bb85aa7391c4d5aeeb68d0c3bd23eae6fafb8a51a5527 |

New comparator, generated wrapper and exact wire hashes cannot be claimed until
the new source closure exists. Old source pins must remain unchanged.

## Proposed architecture for review

Use an additive historical verifier, continuation capsule validator,
checkpoint-03 loader and seq-04-only executor. Do not modify, monkeypatch or
renew original live_plan, verify_chain, next_step or FixedAdapter.call.
Keep original guest Facts inputs separate from new execution identity.

The historical verifier must verify exact retained bytes and all referenced
accepted transport/evidence records, as well as original chronology and native
capture bindings. Expiry is permitted only for historical verification, never
for operational authorization. Missing evidence fails closed.

The capsule binds all historical hashes, full receipt prefix, baseline/snapshot,
fresh UTC and boot/process-scoped monotonic deadlines, exact new source closure,
comparator, watchdog, wrapper and wire, and only seq=4 compare-after-start.
Creator authority must come from a separately trusted protected authorization
record and independent reviewed source-closure approval; a self-declared creator
or a content hash by itself is not authority. Actual local authority interfaces
must be audited and specified before implementation.

A durable exclusive dispatch claim blocks concurrent invocation and replay,
including after controller restart, across continuation IDs for the same original
run/seq. Claimed but unresolved work remains UNKNOWN; it cannot automatically
retry. Publication uses a fully flushed staged receipt and non-replacing atomic
commit in the same protected directory. Recovery may validate and publish an
already complete retained candidate without repeating execution, only through
a separately reviewed recovery procedure.

Receipt 04 retains the original run/seal and predecessor tip and additionally
binds continuation identity/seal, exact evidence hashes, fresh checks, true
comparator PASS, SSH exit 0, normal retained-handle watchdog settlement, inventory
and postflight. Missing/corrupt journals, wrong Facts, timeout or unknown exit
prevent PASS. Commit publication must not change any original receipt.

After receipt 04, stop and report a separate resume gate. Marker/restore remain
unavailable in this executor, including when receipt 04 is PASS.

Alternatives considered: renewing the original plan would invalidate historical
bindings; using another diagnostic package would still fail canonical receipt
acceptance. The additive protocol preserves both historical identity and fresh
execution authorization.

## Remaining gates

Written design and implementation plan review, implementation, twelve requested
RED-to-GREEN cases, independent review PASS, fresh VM/provider/clock/ownership
reconciliation, and one canonical seq-04 execution remain outstanding.
Continuation ID/seal: NOT CREATED. New authorization: NOT ESTABLISHED.
Actual seq 04: NOT RUN. Canonical receipt 04: NOT CREATED.
Resume gate: BLOCKED. Agent runtime changed: NO. Mass rollout: NO.
This is not completion of Task 13 or implementation of the continuation protocol.
