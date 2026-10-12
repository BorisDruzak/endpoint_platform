# Task 13: PID observation investigation and new admission preparation

Scope: investigate the retained D/E discrepancy and prepare one new read-only
admission for a future seq04. No seq04, execution authority or claim issuance.
Code revision remains `36ebfb5bc4f8b0d5ad9b490da8105262cccb6e3a`;
protocol source SHA-256 remains
`0b6ef3462f5964ec99e42abc381794615ec90fc8bd3f0c9057129fcb4bc33a91`.
Original plan/receipts, consumed claims and all guards remain unchanged.

## Proven collection and refusal mechanism

The sealed `Observe-NativeWrapperCurrent.ps1` source SHA-256 is
`596b95d80226da5177e5729918dcf765dc38fcd4d5f7b86007658b6d0fcf5041`.
Its known-PID loop uses one filtered Win32_Process CIM query per historical
numeric PID. It records only pid, present and error_type. Those rows do not
contain birth identity or individual capture timestamps.

`Observe-Task13ProcessIdentity.ps1` instead records two OpenProcess/native/CIM
samples and, for a present process, retained-handle birth/image/session checks.
Absent classification requires both native failures with error87 and both CIM
counts zero. Other errors or incomplete/racing identity fail closed.

The unchanged `loader._reconcile` schedules both collectors concurrently in
its six-worker pool. They do not share a snapshot or retain one common handle
for the known-PID presence check. Aggregate output UTC and overlapping transport
brackets cannot establish the ordering of each historical row's captures.

For E's historical reference index3, the CIM-only current row was present=True,
error_type=None. Independent identity was PROCESS_ABSENT: both samples were
ABSENT/error87/CIM count0, with no row error or observer collision. All other
known/pair rows admitted. D's same reference was present=False/PROCESS_ABSENT.
Offline replay of the exact sealed validator admits D and refuses E at the
identity-presence conjunction. Thus E's NO_GO is a correct guard refusal,
not command truncation, packet substitution, transport timeout or proof of
an active original process.

The cross-sample discrepancy is proven. The historical occupant, its lifetime,
cache effects and the underlying cause of that discrepancy remain UNKNOWN.
A hypothetical short-lived/reused PID is not asserted as an observed event.
No guard is relaxed and no old observation is rewritten or promoted to PASS.

Independent E refusal proof SHA-256:
`9ac16407edef020d495c4423cbfa3d88d38ce3b2d01e283486b8b763b7034d82`.
Historical preservation SHA-256:
`49b3707bd72a001c730c77c39a0608d204a13a80c83bb58c812120cabb3a3ac1`.

## New gate procedure

F is a new immutable read-only evidence bundle. It uses the same committed
protocol, source/runtime verification, all eight sealed packets and unchanged
freshness/identity predicates. It requires independent exact source review,
one native read-only observer, complete native settlement and independent
admission review before final gate publication. Any refusal retains NO_GO;
there is no automatic retry or selection of a favourable historical sample.

F PASS establishes fresh consistency at its recorded observation window.
E's historical occupant remains UNKNOWN; future consistency must be rechecked.
Actual execution still requires a separate valid bound human authorization,
the unused durable recovery slot, and complete repeated preclaim and immediate
prelaunch checks. Scope remains one seq04; STOP before seq05.

## F independently verified observation

F source closure SHA-256:
`109e1e2a0f23dc2ad04573087174adc0bad50a321137e21c6427b7b5ad17a821`.
Independent exact review verified 85 source entries, 2,879 accepted runtime
files and all eight sealed packet/binding/bootstrap reconstructions.
One native read-only observer exited0, wait0, with complete streams and no
timeout. All eight constituents and all 16 historical PID references passed
the unchanged predicates. The previously inconsistent reference is now
current present=False and native PROCESS_ABSENT. No original activity or
historical disappearance chronology is inferred from this fresh PASS.

| Evidence | SHA-256 |
| --- | --- |
| Independent source review | 90e67980337235dd119cf46566a4af7a44547d263c31e6cf93b1b8ae94f61d9f |
| Independent recovery source review | 1f132d83b2af28221aad5db99d18bf9ae48af8daffb4e715b932ccb4784eeff2 |
| Native read-only exit | 394709844fa419c6f7f0094cc9565c5f90e4b509ca8e1ab42e3bacedf69117df |
| Full preflight | dbbe5f39f680f3baabf7cf79ff26fd96f3d62d97f9b18ba1c5c38b2d7969996e |
| Independent admission review | dbb981386c980cf88ec340a388831cb3683b8e316f141fed033df02bfdbea688 |
| D/E/F collector-mechanism review | efea17c925b7183c4f49c412ec91354ef70c6653ec252496e3d38403a12f33aa |

The fresh observation checked UTC is 2026-10-12T10:21:33.176206+00:00.
The existing protocol caps a separately bound authorization deadline at
2026-10-12T10:41:33.176206+00:00, with full remaining budget required before
claims. Source/runtime code and guards have not changed; the prior 83-test
recovery and 352-test applicable Task13 results are not represented as rerun
in this operational read-only preparation.

## Final gate and STOP

Final status: READY_REQUIRES_SEPARATE_AUTHORIZATION.
Final gate SHA-256:
`2dc86cf6a01090a2c146fb3b0b7b7e07c35af55f868c205913bacd3154f407a1`.
Verified admission evidence SHA-256:
`95f7d968756f8c6d589ba06293accb04d3d5c7ead7db299a1bb631f74bcdffa3`.
Final preservation record SHA-256:
`3294f24a2cd0fa36ea4eec87ec7d06820426396e21cdf3b54b00a6cbf0182845`.

Four historical checkpoints, original plan/seal/deadlines/receipts/Facts,
baseline/snapshot and all three consumed claim bytes/hashes are unchanged;
historical preservation digest is still `49b3707...3ac1` as recorded above.
Recovery slot remains ABSENT. Maximum command UTF-16 units including NUL:
7,796 total; 7,659 remote; 325 isolated root. No authority, new execution
claim, seq04, receipt04, seq05, marker, restore or runtime change occurred.
No old authorization is renewed or applied to F.

The durable protected gate and reviews are retained under the evidence
bundle `task13-additive-recovery-observe-20261012-f`. The gate is preparation
for one separately authorized seq04, not permission to execute it or a fleet
readiness decision. STOP after read-only readiness verification.
