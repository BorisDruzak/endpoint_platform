# Task 13 Continuation Protocol v1

Date: 2026-10-11. Status: proposed written specification, awaiting user review.
Repository baseline: `9144a26472239e5a4c61a79aacdabbda4ec961bc`.

## Purpose and boundaries

Resume only canonical seq 04, compare-after-start, after expiration of the
original Task 13 plan. Preserve the original plan, run seal, receipts 00–03,
guest baseline and snapshot. A successful receipt 04 opens a separate resume
gate; it does not complete Task 13. Marker, restore and all later steps are
unavailable in this protocol version's executor. Agent 3.2.82, MSI, Setup,
Endpoint provider and published runtime artifacts remain unchanged.

The original controller/runner/adapter and their source pins remain immutable.
Do not monkeypatch clocks or live_plan, replace the old plan, edit old receipts,
or promote diagnostic results into recovery receipts. Old live_plan,
verify_chain and next_step must continue rejecting the expired original run.

## Audited interfaces

The private canonical closure was inspected directly; GitNexus covers the
committed repository, whose indexed commit matches this baseline.

`FixedAdapter.guest(step, plan, seal, snapshot, base, clocks, deadline)` passes
original RunId and digest(plan) to the guest, pins the original helper, builds
exact-count wire/wrapper bytes and persists their dispatch bindings.
`FixedAdapter.call` itself calls original live_plan before bounded transport.
It cannot serve as the continuation executor without changing authorization.

`verify_chain` combines live authorization with original predecessor,
chronology, snapshot, LVM and generation checks. `next_step` uses that function.
The old runner starts with receipts empty and a new capture. No checkpoint-03
loader exists. The new loader therefore belongs to a separate module.

Guest Facts embeds original run_id and plan_sha256. Its entire serialized
projection is compared against the baseline. Continuation identity belongs
only in execution control, transport correlation and new receipt fields.

The original supervisor authenticates its local source closure by pinned
manifest/controller hashes and validates protected local inputs. It does not
provide a reusable continuation-authority API. Continuation authority is a new,
explicit local trust boundary described below.

## Immutable anchors

| Anchor | SHA256 |
|---|---|
| Original plan | bbddf13f084c6be9c7fed8fc2041df88953aabb33915ce12631eeab0f1c7fa5d |
| Original run seal | 6f30d2b3698498f4daa55aa2a8f1fd6e4181e3a20498c8ce8a7de4da37d74590 |
| Receipt 00 | cfee02365b325be914625d0e17155d2dcf50707158f21fc571516fc83c0f579c |
| Receipt 01 | 3dfa3995369e4c2052de8d8f6f4dee878fe3596fccb386e9af758e6c641c57ed |
| Receipt 02 | bab49be079688046908ae66c8e4ff0b75260b7fe3d10f11c76ca2243640ca5cb |
| Receipt 03 / tip | cdd42d87efa105f78957240838b96e0232784869d36f5335396aa341168cf4fd |
| Baseline | cdbdf079698747b2af32e7749291388099f04275e10c13995616c8d1206e1534 |
| Snapshot identity | 923000023d7996498bd6ce51b822a171e626c04335c9403cd2e1f7d1e59074d5 |

Both raw-file and canonical-object hashes are checked. JSON uses bounded UTF-8,
unique keys, exact schemas, no NaN/Infinity, no Boolean-as-integer coercion and
canonical sorted compact ASCII serialization for object digests. Source files
are compared byte-for-byte; normalization does not change historical evidence.

## Historical verifier

`verify_historical_prefix` is non-operational and returns a validated checkpoint
03 binding. It accepts expired historical authorization only as history. It
must not dispatch or return a live execution capability.

It verifies exact bytes of original plan/seal and all four receipts; equality
of seal.plan and plan; original fixed duration and run/snapshot identity;
all predecessor and original UTC/monotonic chronology checks; original snapshot
creation bracket/configuration/volume identities; capture and native evidence;
and unchanged pre-rollback VM generation and current-volume identity.

The original retained transport schema has accepted parsed observations and
typed byte counts, candidate/dispatch records and caller-acceptance flags; it
does not retain outer raw stdout/stderr or their hashes. Verify the actual
retained schema and original receipt digests. Do not reconstruct missing raw
bytes, fabricate historical transport evidence or claim that byte counts prove
raw-output integrity. Raw output retention is mandatory for new execution.

It also resolves every referenced transport, ownership, clock, inventory,
source-dispatch and postcondition record from the protected retained closure.
Every reference must resolve uniquely to its canonical typed object within an
exact retained file, satisfy its original schema and bind the appropriate
original dispatch. Native capture, source pins,
payload manifest and original source closure are verified. Missing or ambiguous
evidence fails closed. Corroborating ownership/source-dispatch records that were
not cryptographically referenced by the original receipt are checked as retained
records, without claiming a nonexistent original hash link. A new continuation
closure seals their current raw hashes separately; it cannot retroactively add
links to original receipts. Dynamic relationships are checked against source; a
negative GitNexus query cannot establish absence of a dependency.

The historical gate has no current-clock override parameter. Freshness of
historical observations is assessed at their original recorded event brackets.
Preserve explicit HISTORICAL_GUEST_CLOCK_NOT_FRESH entries for snapshot/start
while the guest was unreachable, including their last_validated_bracket. They
are historical evidence only and cannot satisfy a new fresh-clock gate.
Freshness for new execution is a separate live gate using actual current time.

## Capsule and creator authority

The format is `task13_continuation_v1`, version 1. It has exact top-level fields:

- schema, version, continuation_id (canonical random UUID), allowed_seq=4,
  allowed_step=compare-after-start;
- original binding: original run_id, original plan/run-seal hashes, ordered
  receipt 00–03 raw/canonical hashes, original tip, baseline and snapshot hashes;
- authorization binding: protected operator-authority record hash and
  independently approved source-review record hash;
- clocks: created_utc, expires_utc, root created/deadline monotonic nanoseconds,
  root host/boot identity, root controller PID and native process birth;
- budgets: authorization 1,200 seconds, comparator workload 120 seconds,
  retained-handle settlement 10 seconds, SSH workload observation 145 seconds,
  final local persistence reserve 2 seconds;
- source_closure: exact named entries, byte sizes and SHA256 values, including
  loader, historical verifier, authorization/receipt validators, local storage,
  transport, generated comparator, fixed MSI reader, aggregate profiler,
  watchdog, journal writer, wrapper bytes and wire bytes;
- execution binding: exact expected guest/target identity, expected original
  guest Facts identity and exact command/argument digests.

The content hash is the capsule seal; it is an integrity digest, not a signature
or proof of creator authority. The protected authority record is created only
by the reviewed local bootstrap under a verified elevated administrator or
SYSTEM token. It records the actual kernel token SID, host/boot/process identity,
authorized original anchors and seq=4, approved source-closure digest, reviewed
bootstrap digest and the retained explicit human request reference/digest.
Create this intent record before the capsule. A separate protected creator
attestation binds its hash to the exact final capsule digest; its digest is
pinned outside the capsule. This avoids a capsule/authority hash cycle. The executor
accepts it only from an independently selected protected authority location,
with a bootstrap-pinned digest supplied outside the capsule.

The independent review record must be PASS, bind the final source-closure
digest, name the reviewer and scope, and have its exact hash pinned by the
bootstrap. A capsule cannot nominate a replacement authority or review record.
These trust records are protected local evidence, not repository configuration.
The request reference contains no credential material or raw private topology.

Trust assumption: local elevated administrators and SYSTEM are trusted to
create operator authorization and preserve the review record. This is a local
ACL-backed authorization protocol; it does not protect against a hostile
administrator or claim remote cryptographic nonrepudiation.

Capsule, authority, closure and dispatch inputs use protected BA/SY-owned
directories/files, explicit restrictive DACLs and checked ancestors. Reject
reparse points, symlinks, extra hardlinks, path traversal, case aliases and
replacement races. Verify metadata and contents through retained handles at use
time. Current authority token and actual host/boot/process identity are observed
by the trusted bootstrap, never accepted as caller-provided facts.

## Time and restart behavior

Generate fresh UTC and local monotonic deadlines without adjusting any system
clock. Both domains must be live before every remote dispatch and publication.
Reject wall-clock rollback or divergence from the monotonic elapsed interval
beyond the five-second validated clock bracket. Remote guest/hypervisor clocks
use fresh bounded brackets; maximum bracket age at dispatch is five seconds.
Remote monotonic values are never compared numerically with root monotonic time.

The capsule is bound to one root controller process and boot. Root restart or
reboot invalidates it; persisted deadlines are not reused in another clock
domain. A replacement continuation for a historical tip does not clear the
original seq-04 dispatch claim. Unresolved execution requires a separately
reviewed recovery procedure; this version supplies no automatic recovery run.

Workload timeout is 120 seconds. An independently started watchdog must be
armed against the exact PID/native birth and retain its handle before comparator
work begins. Handle settlement gets its explicit ten-second budget; a timed-out
or terminated workload remains UNKNOWN even if termination is confirmed.
The 145-second SSH observation budget does not extend the workload limit.
Each operation also fits the remaining capsule budget minus publication reserve.

## Source closure and comparator

Use these exact committed candidates, retaining the original helper unchanged:

| Source | SHA256 |
|---|---|
| Get-Task13MsiTables.ps1 | 13c5a93944ee4b4386e3f81f2dcf0cdde020864949b7b480f3e15d55af73d3fc |
| Task13AggregateProfile.ps1 | 0221009b6857f633c4117e65bfd6d1d02bea3079ca20717f5777d9e3a41422b4 |
| Watch-Task13DiagnosticProcess.ps1 | b5d547a1b5d865ff7f3bb85aa7391c4d5aeeb68d0c3bd23eae6fafb8a51a5527 |

The deterministic comparator builder derives a separate compare-only helper
from the verified original, replaces only the audited NativeRows implementation,
and incorporates the reviewed reader/profiler and protected diagnostic journal.
Assert exact patch boundaries and parse the generated PowerShell 5.1 source.
Remove operational access to capture, marker and restored actions in this new
entry point; preserve Facts and PublicProof observations and serialized layout.
Generated wrapper and exact wire get their own hashes. No cyclic hashing:
guest wire carries original Facts inputs and the execution continuation_id,
but no capsule seal derived from those same wire bytes.

The loader must generate and validate a new closure before capsule creation;
old helper pins are never substituted. Per-use checks verify retained exact
bytes for every loaded module, dispatched script and command. Protected journal
validation covers framing, sequence, event pairing, execution/process identity,
durable phase summaries and complete native profiles. Corrupt, missing or
unfinished journal evidence cannot support PASS.

## Execution and receipt publication

The loader validates checkpoint 03, authority, review, closure and live capsule.
Fresh preflight observes VM running state, snapshot/config/volumes, original
baseline bytes/Facts, recovery-leaf inventory, SCM/MSI/update-state quiescence,
clock brackets and provider version/session/ownership. Require no active update
owner/recommendation and a fresh matching authenticated session. Source and test
verification preserve the existing provider/ownership semantics.

Before preparing or starting the watchdog or comparator, exclusively create
and flush a dispatch claim keyed by original run-seal/tip/seq, shared across all
continuation IDs for that run. This is the linearization point for at-most-once
execution. An existing claim refuses dispatch, including concurrently and after
crash. Failure after the claim remains UNKNOWN and never silently clears it.

Execute only compare-after-start through the new canonical loader. The new
transport applies continuation liveness directly; it does not route through
FixedAdapter.call or weaken the old controller. Reuse audited pure observation
and validation primitives only where their interfaces and dependencies permit.
Retain stdout/stderr before parsing, complete typed transport evidence, exact
source/wire bindings and native watchdog evidence in a protected new evidence
root. Do not write diagnostics into the original guest recovery directory.

Require GUEST_COMPARATOR_PASS, SSH exit 0, confirmed normal native exit through
the watchdog's retained handle, no termination, complete valid diagnostics,
original Facts identity, unchanged baseline/snapshot and fresh valid postflight
provider/ownership/inventory/clock observations. A transport return by itself is
an unaccepted candidate. Native proof and provider freshness are checked at use.

Receipt schema is `task13_continuation_receipt_v1`. Receipt 04 includes original
run_id/run_seal_sha256, seq=4, step, previous_sha256=original_tip, original_tip,
baseline/snapshot hashes; continuation_id and capsule hash; COMPLETE status;
new-domain UTC/monotonic brackets; and exact source, wire, authority, review,
claim, guest/transport/watchdog/journal and pre/postflight evidence digests.
The new receipt verifier checks the historical prefix plus capsule and new
evidence. It never claims that the old live verify_chain accepts the new run.

Stage the full validated receipt in the original protected records directory,
flush it, then publish `receipt-04-compare-after-start.json` using a same-volume
non-replacing atomic operation through verified handles. Confirm publication
and retained bytes within the deadline; rehash 00–03 and every immutable anchor.
Never overwrite an existing receipt. A crash leaves either a complete committed
receipt or an uncommitted candidate; old history remains intact. A candidate
cannot cause another execution. No automatic candidate adoption or replay is
implemented without a separate reviewed recovery procedure.

## Implementation units

New source is confined to tools/canary/task13_continuation/ and focused tests
under tests/tools/. Separate modules own strict codec/types, historical
verification, authorization/deadlines, source/comparator building, protected
storage/claims/publication, controlled observation/transport, receipt validation
and the one-step loader. Local identity/configuration, authority records,
original private closure and generated operational evidence stay outside Git.
No dependency addition is required for pure validation; inspect exact pinned
versions and Context7 before any library-dependent integration change.

## Verification and independent review

RED-to-GREEN must demonstrate all twelve requested cases with real assertions:

1. Original expired executor still refuses without clock/function alteration.
2. Valid continuation accepts only the complete verified four-receipt prefix.
3. Plan/seal/receipt/baseline/snapshot tampering refuses before dispatch.
4. Comparator/watchdog/transport substitution without a new seal refuses.
5. Wrong serialized guest Facts refuses PASS.
6. Expired capsule refuses without adjusting time; wrong boot/process refuses.
7. Receipt 04 requires actual comparator PASS and complete accepted evidence.
8. UNKNOWN/timeout/corrupt journal/unconfirmed exit never create PASS.
9. Concurrent/restarted/replacement-capsule invocation cannot repeat execution.
10. Marker/restore reject even after receipt 04; no step skipping is available.
11. Fault injection before/after each receipt-publication boundary preserves
    history and exposes only a complete receipt or an uncommitted candidate.
12. Runtime/installer/provider source and published artifacts remain unchanged.

Synthetic tests are explicitly non-operational and cannot supply live authority
or canonical acceptance evidence. Test the actual private historical prefix
locally after generic regressions; do not commit its identities or records.
Windows-native tests prove protected handles/ACL checks, no-replace publication,
concurrent claim exclusion and watchdog normal/timeout/unconfirmed-exit paths.

Before any VM operation, an independent reviewer inspects final capsule authority,
historical invariants, exact closure, deadlines, replay/rollback, crash-safe
publication and absence of old-check bypasses. Pin a PASS review to exact final
source bytes; any subsequent change invalidates it until re-reviewed.
Only after this gate and fresh reconciliation run actual seq 04 once.

## Reporting and stop condition

Report implementation commit SHA, all original anchors, schema/version,
continuation ID/seal, exact comparator/watchdog/wrapper/wire hashes, immutable
prefix check, historical verification, new authorization, RED-to-GREEN results,
independent review, actual seq-04 outcome and canonical receipt creation.
Report a separate resume gate, next-step authority, unchanged Agent runtime and
NO mass rollout. Seq 05 may be the next sequence position but is not authorized
by this capsule. A receipt-04 PASS must never be reported as Task 13 completion.
