# Task 13 additive recovery admission v1

This implements the previously reviewed `TASK13-SEQ04-47B688C-RECOVERY-20261012-A`
gate and the operator's additive recovery protocol requirements. Baseline:
`47b688c8cc926a9ac43e36426d69b07234f34cad`.

## Scope and immutable boundary

Separate recovery modules and entry points; ordinary admission, authority,
storage, receipt and transport implementations remain byte-identical. No agent,
MSI, Setup or runtime change. No real execution claims or seq04 during development.
Original plan/seal/deadlines, receipts00–03, guest Facts, baseline, snapshot and
three consumed claims are retained. Historical identity RCA remains UNKNOWN.

## Historical admission

Recognize only the pinned failed attempt: global/launch claims consumed, exact
original binding, prepare builder refused with `Windows command-line bound`
before any prepare or workload transport, native root exit1/wait0/complete streams.
Verify exact old source/evidence trees and claim owners, not an absence-only
inference. Hold historical sources and consumed claims through execution.

## Slot and crash semantics

Uniqueness key contains original seal, original chain tip, seq4 and the consumed
global claim SHA. It excludes revision, CID, request, deadline and gate ID.
Slot content binds full original prefix, protocol source digest/revision,
continuation identity, exact source/runtime closure, actual authorization,
parent native identity, fresh admission evidence and finite deadline.

States: ABSENT -> LAUNCH_COMMITTED -> DISPATCH_COMMITTED -> terminal evidence.
Commit the final exclusive native CREATE_NEW name directly. Flush empty occupancy,
then canonical payload and volume metadata. Any empty/partial/unknown slot is
permanently burned; never repair/delete/reissue it. Child dispatch transition
also uses one exclusive permanent name. A crash/restart after either transition
allows observation/settlement only, never another launch or workload dispatch.
This is fail-closed process-crash handling, not a claim of power-loss certification.

## Execution authorization and source review

Implementation/read-only requests do not grant execution. Capture only the latest
actual human app-session message using a separate versioned format binding the
read-only admission gate SHA, implementation revision, protocol source digest,
CID and finite UTC deadline. Reject quotes, replay, expiry or changed latest user.
The human authorizes a reviewed gate; final bundle review subsequently binds the
exact operator record. Keep hashes separate to avoid a closure/request hash cycle.

Before the first new claim: retain native source/runtime/ancestry handles; verify
full sealed stdin length/hash/body/source/parameter pins, exact generated command
and every shell layer including UTF16 NUL (<8192), exact interpreter/dependency
closure, live authority, full remaining budget and fresh canonical reconciliation.
Before actual workload: repeat authorization, claims/history, exact commands,
fresh reconciliation/identity/ownership/clocks and bounded dispatch freshness.

## Parent and child

Parent owns its preclaim capsule and read-only preflight. Child owns a distinct
native creator capsule. Parent registers child PID+birth from retained Popen
handle; child checks that registration and parent native liveness before its
exclusive dispatch transition. Both must differ from the independent reviewer.
Parent observes child native exit, complete bounded streams and exact publication.

## Recovery receipt

Use an explicit recovery evidence/receipt schema with genuine old consumed
claim plus new recovery launch/dispatch records. Never fabricate a legacy
dispatch claim for a new CID. Preserve comparator, journal, native watchdog,
pre/postflight, source, original-tip and root-exit predicates in the separate
verifier. Receipt04 requires independent verification; STOP before seq05.

## Read-only completion gate

Publish source/review hashes, RED/GREEN matrix, historical preservation proof,
slot state and read-only reconciliation. Ready protocol does not mean execution
authorized. No slot is issued during preparation. Future execution repeats fresh
live predicates; old read-only PASS cannot authorize it.
