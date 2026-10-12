# Task 13 natural consent v2

The operator explicitly requested protocol repair, independent review, a fresh
gate and one seq04 attempt, without copying a machine-generated JSON directive.
They separately confirmed intent to continue the remaining original plan.

## Authorization boundary

The new v2 path recognizes the complete supported direct human request in the
actual Codex app session. It preserves the raw request frame, its index, thread,
timestamp and SHA, and the exact subsequent scope clarification frames. Ambient
browser context is excluded from the request. Assistant, quoted, example,
implementation-only and unsupported later user messages do not authorize
execution. Any later unsupported or restricting message fails closed.

The machine derives an explicitly versioned request envelope from this consent
and the independently finalized admission gate. This envelope is not represented
as a user-authored JSON message. The selected gate, implementation revision,
protocol source, continuation ID and consent are pinned in the reviewed execution
closure. Consent expires after two hours; the selected gate expires after at most
20 minutes, with the earlier deadline controlling. Complete launch budgets and
all repeated preclaim/predispatch checks remain mandatory.

The strict v1 parser remains byte-identical. v2 has separate bootstrap entry
flags, and rejects mismatched CLI, control, gate and request versions before
authority/slot creation. All authorization logic is included in the protocol
source digest. Existing transport and native process/watchdog verification remain
unchanged.

## Durable history

Both versions use the same original-seal/tip/seq04/consumed-global-claim slot key.
Changing consent, CID, version, gate or deadline cannot create a second slot.
Partial writes and uncertain occupied states remain permanently fail-closed.
All three historical consumed claims and original plan, seal, deadlines,
receipts00–03, baseline, snapshot and Facts are retained unchanged.

## Continuation boundary

User intent now includes seq05–11, but this recovery executor still permits only
seq04 and publishes STOP_BEFORE_SEQ05. The original plan expired and its legacy
verifier cannot accept an additive seq04 receipt. Later steps require a separately
reviewed additive continuation path and real canonical predecessor evidence;
neither the original deadline nor its legacy verifier may be changed to bypass
that boundary. Runtime3.2.82, MSI, Setup and mass-rollout scope are unchanged.

## Verification

Natural-message tests were first RED because the versioned path was absent.
Boundary regressions additionally demonstrated that mixed v1/v2 controls reached
their handlers before explicit version checks were added. Tests cover actual
frames, ambient context, exact clarification, replay/raw history edits, expiry,
source/gate identity substitution, revocation and cross-version slot concurrency.
Test counts and independent native admission/execution evidence are recorded
separately after their actual verification; this document is not execution proof.

The full Task13 test selection on Windows/Python3.12 completed with 379 passed
and nine historical-state failures in 254.57 seconds. The failures are unchanged
legacy guards: three readonly-recovery tests expect an unconsumed original seq04
claim, and six actual-session tests expect a previous permission literal. The
current consumed history and actual natural request correctly fail those guards;
the guards and historical inputs were not modified. The new natural suite has
26 passing tests, independently repeated by the security reviewer. Native
concurrency/crash/restart and mixed-version slot tests passed in the full selection.

Historical-state failures:

- `test_capture_readonly_recovery_preserves_consumed_claim`
- `test_changed_consumed_claim_blocks_readonly_recovery`
- `test_changed_readonly_record_refuses_under_retained_handles`
- `test_actual_new_request_scope_denies_execution` (two legacy entry variants)
- `test_caller_quote_cannot_turn_guard_scope_into_execution`
- `test_separate_permission_binds_actual_message_and_prior_gate`
- `test_actual_execution_request_has_distinct_scope`
- `test_actual_execution_permission_binds_independent_admission`
