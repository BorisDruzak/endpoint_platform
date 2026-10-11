# Task 13 PID identity guard correction

Scope: replace numeric known-PID absence with instance identity, preserving all
other continuation predicates. Read-only inspection/review/fresh VM reconciliation
only in this stage; seq04 is a separate step requiring full gate confirmation.
No SSH service intervention or process termination.

## Reference evidence

The sealed known list has fourteen slots and two separately inspected pair slots.
Fourteen slots have no saved birth identities; pair0 has historical native/CIM birth
and parent, pair1 only a parent relation. Do not invent missing original identities.
All sixteen have an accepted, pinned absence witness at checkpoint observation
2026-10-09T06:45:30.5166660Z. A stable native creation time after that witness proves
a different instance. An earlier unexplained instance or contradictory evidence is
IDENTITY_UNKNOWN. A saved exact original birth when available detects an active
original even if its image changes; it must remain blocked.

## Native observation

Observe each PID twice with retained QUERY_LIMITED_INFORMATION|SYNCHRONIZE handles.
Bind native PID, exact FILETIME creation, image path/hash, SessionId, handle count,
wait state, and bounded selected CIM creation/image/parent/session metadata. Reopen
the same PID while retaining the first handle; require equal identity and no exit.
Absence requires two native absent results and consistent empty CIM samples.
Access denial, field omission, inconsistent native/CIM identity, termination/restart,
or timeout is IDENTITY_UNKNOWN. Parent information and available handle counts are
retained; command lines are neither queried nor persisted by the new observer.

## Classifier and integration

States: ORIGINAL_PROCESS_ACTIVE (blocked), PID_REUSED (eligible), PROCESS_ABSENT
(eligible), IDENTITY_UNKNOWN (blocked). State is recomputed by controller predicates,
not trusted from a guest label. Registry bindings include original plan/seal/tip,
VM identity, fixed reference artifact hashes and exact ordered PID slots.

Add identity as an eighth raw-retained reconciliation constituent. A pinned AST
substitution replaces only the two original numeric `present is False` checks for
known/pair loops with identity admission. All surrounding exact schemas, PID types,
observer exclusions, error checks, wrapper scans, leaves and preserved baseline
conditions remain unchanged. Numeric observations and identity observation must
agree on presence; disagreement fails closed. Original source files stay immutable.

Keep freshness/deadlines, source closure, original receipts00–03, baseline, snapshot,
VM generation, owners, SCM/MSI/update, inventory, clocks, watchdog, journal, raw
transport, atomic publication and original/recovery claims unchanged. Old original
executors remain expired. Independent review must verify the substitution is narrow
and all preserved conditions still reject tampering.

A fixed protected read-only entry creates an explicit observation window, validates
all eight constituents and reports READY_FOR_SEPARATE_SEQ04 or BLOCKED. It creates
no seq04 authority capsule, root launch, recovery/workload claim, watchdog or receipt.
The current actual human message is bound as guard-only permission; execution flags
for seq04 must reject this scope before launching a root.
