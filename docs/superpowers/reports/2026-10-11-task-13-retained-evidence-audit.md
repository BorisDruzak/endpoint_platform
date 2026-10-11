# Task 13 retained-evidence audit

Date: 2026-10-11. This supplements the initial local audit and refines the
continuation design against actual retained schemas. No operational dispatch,
VM access, provider access or runtime mutation occurred.

## Source closure

The original source-closure manifest raw SHA256 is
`6abe8fc674d09f2f0d1deabc07494d54c0b2d6d16ed2fa307c269900227226cb`.
All 61 source entries and 305 prerequisites match their declared byte sizes and
SHA256 values. This audit did not mutate them or refresh their source pins.

## Retained links and predicates

A separate local read-only audit loaded the unmodified original controller's
pure canonical digest/time helpers and checked retained records directly.
The final command returned exit 0 and these counts:

| Check | Count |
|---|---:|
| Receipt transport digest resolved uniquely to accepted envelope | 4 |
| Capture observation and native proof bound to run seal | 1 |
| Baseline recovery-leaf inventory bound to receipt | 1 |
| Fresh clock bracket resolved and fresh at original dispatch | 6 |
| Explicit historical guest clock bracket preserved | 2 |
| Retained provider zero-owner observations before receipt 03 | 4 |
| Original guest source-dispatch helper/plan binding | 1 |
| Management action/postcondition and empty active-task evidence | 3 |

For each main transport, the accepted record equals the persisted unaccepted
candidate with exactly the source-defined acceptance substitutions. Candidate
and dispatch identity/timestamps match; confirmed stdin/dispatch/persistence,
typed SSH exit 0, no error bytes and original receipt bookends were verified.

Receipt 00 observation/native digests match seal.capture_sha256/native_sha256;
original plan, run and baseline bindings match. Inventory contains only the
protected, non-reparse, single-link baseline with the expected hash. Management
action records match receipt postconditions; actual before/after LVM rows,
typed successful exits, empty active tasks and ordered observation/action
ordinals agree.

Before/after raw hashes of all 231 JSON files in the original records directory
match. This check establishes no mutation during this audit; cryptographic
historical authenticity comes from the original anchor/reference relationships,
not merely from a before/after comparison made today.

## Schema correction found during audit

The first audit command failed on a missing root_dispatch_utc key. Inspection
of the actual records and original runner established the cause: receipts 02/03
intentionally wrap the last guest bracket in
HISTORICAL_GUEST_CLOCK_NOT_FRESH while the guest is unreachable. The corrected
read-only audit validates the referenced bracket but does not require or claim
guest freshness at those later dispatches. Six genuinely fresh brackets and
two explicitly historical brackets are reported separately.

## Existing evidence limits

The original outer transport records contain accepted parsed JSON observations,
typed output/error byte counts and caller acceptance; raw stdout/stderr and
their hashes were not retained in this schema. The audit therefore validates
the original retained observation/transport digests and their source-defined
bindings. It does not retroactively verify absent raw bytes or recreate them.

Original ownership and source-dispatch records provide corroborating retained
evidence where original receipts do not reference their entire raw hashes.
Their successful predicate checks must not be described as an original
cryptographic receipt link. Continuation can seal their current bytes in its
new historical-evidence manifest without modifying any original object.

The guest baseline bytes and current VM/provider/ownership state were not
observed in this local audit. Those checks remain mandatory after independent
implementation review and before actual seq 04. New execution must retain raw
stdout/stderr before parsing and bind their exact hashes in the new receipt.

Implementation, RED-to-GREEN, independent source review and controlled seq 04
remain outstanding. Continuation authorization and receipt 04 are NOT CREATED.
Agent runtime changed: NO. Mass rollout: NO. Task 13 is not complete.
