# Task 13 Continuation Protocol v1 — controlled acceptance

Date: 2026-10-11. Scope: implement an additive independently reviewed
continuation, attempt only seq 04, then stop before seq 05. Task 13 is not
complete; marker, restore and product/fleet acceptance remain outside this run.

## Acceptance ledger

| Field | Result |
|---|---|
| Implementation SHA | `ccfaa5956f5790cb7460c1fcec426aacc8c0fbbe` |
| Original plan SHA | `bbddf13f084c6be9c7fed8fc2041df88953aabb33915ce12631eeab0f1c7fa5d` |
| Original run seal | `6f30d2b3698498f4daa55aa2a8f1fd6e4181e3a20498c8ce8a7de4da37d74590` |
| Original chain tip / receipt 03 | `cdd42d87efa105f78957240838b96e0232784869d36f5335396aa341168cf4fd` |
| Continuation schema/version | `task13_continuation_v1`, version 1 |
| Continuation ID | `7a708702-3be1-4e55-89af-081b66947889` |
| Continuation seal/hash | `1a6c74a526cee63af080df2e82c7a140f825728ae7d4e31bece33928360cc6ff` |
| Source/control/runtime closure | `1f4c4cbc2928ce85d3647816b7f1825963231eadd94697c05100ca36be859602` |
| Comparator SHA | `86d02667278035372ebfff7ef6a878baa90cfaf9490e9628c4d79412cf87d3ca` |
| Corrected MSI reader SHA | `13c5a93944ee4b4386e3f81f2dcf0cdde020864949b7b480f3e15d55af73d3fc` |
| Aggregate profile SHA | `0221009b6857f633c4117e65bfd6d1d02bea3079ca20717f5777d9e3a41422b4` |
| Watchdog SHA | `b5d547a1b5d865ff7f3bb85aa7391c4d5aeeb68d0c3bd23eae6fafb8a51a5527` |
| Wrapper SHA | `a4f647c94f3fba0fb7c2fd6ebd89ff5ddb480fa688525126260e8c099ab44685` |
| Wire SHA | `e884be622c66aa6f1e4b91220da366c485d825089641bc61bf6d8a45958c97cc` |
| Bootstrap SHA | `f16786b2a4143b65998ceec4860f01e73e77e9b96b3f1a4d2fb17f54153a0cae` |
| Original receipts 00–03 unchanged | YES |
| Historical chain verification | PASS; immutable 61-entry/305-prerequisite closure verified again after refusal |
| New authorization | PASS at initial creator/live gate; seq04 dispatch BLOCKED by preflight |
| Independent review | SOURCE PASS on corrected `ccfaa59` / bundle i; Critical/Important/Minor 0/0/0; no live acceptance |
| Actual seq 04 | NOT RUN; initial read-only preflight UNKNOWN |
| Canonical receipt 04 | NOT CREATED |
| Next authorized step | NONE in this run; no retry after UNKNOWN; STOP BEFORE SEQ05 |
| Resume Gate | BLOCKED |
| Agent runtime changed | NO |
| Mass rollout | NO |

Original baseline and snapshot pins are respectively
`cdbdf079698747b2af32e7749291388099f04275e10c13995616c8d1206e1534`
and `923000023d7996498bd6ce51b822a171e626c04335c9403cd2e1f7d1e59074d5`.
The original manifest raw SHA is
`6abe8fc674d09f2f0d1deabc07494d54c0b2d6d16ed2fa307c269900227226cb`.
Original missing raw stdout was not reconstructed. Historical stopped-guest
clock brackets remain explicitly historical, without live authority.
Continuation ID, capsule seal, comparator/watchdog/wrapper/wire/bootstrap and
source closure in the ledger above describe the single attempted bundle h.
The corrected implementation SHA is reported separately; corrected bundle i
has different control/bootstrap/wrapper identities and was never executed.

## Verification

The actual retained-input full suite on frozen implementation source passed:
**140 passed in 122.35 seconds**, Python 3.12.14, pytest 9.1.1. Command:

```powershell
$task13Tests = @(Get-ChildItem tests/tools/test_task13_continuation*.py |
    ForEach-Object { $_.FullName })
python -B -m pytest @task13Tests tests/tools/test_task13_msi_profile.py tests/tools/test_task13_watchdog.py -q
```

`TASK13_HISTORICAL_ROOT` selected the existing private retained root. No target
was contacted by this suite. Native owned tests exercised Windows security,
retained file/process handles, exclusive claims, concurrent cross-ID replay,
no-replace publication and failure boundaries. Synthetic observations and
mocked authorities in pure/orchestration tests cannot confer live acceptance.
`git diff --check` passed before every implementation commit. A broader tools
run passed 112 tests and skipped 27 opt-in private-input cases; the separate
140-test run above included the actual retained input cases.

| Required RED→GREEN gate | Evidence |
|---|---|
| Old expired plan still refused | Actual original `live_plan`, `verify_chain`, `next_step` all refused; no live gate altered |
| Intact historical prefix only | Missing/tampered prefix and chronology/source/owner substitutions refused |
| Original receipt/plan/seal/baseline/snapshot tamper | Fixed raw and canonical anchors plus actual retained substitution tests |
| Unsealed comparator/watchdog replacement | Closure byte-substitution failures; generated AST and runtime closure checks |
| Wrong guest Facts refuses PASS | Wrong run/plan/baseline/snapshot/status and native proof cases |
| Expired continuation refuses | Expiry, UTC rollback, boot/process mismatch and finalization expiry cases |
| Receipt only follows actual PASS | Raw-bound complete transport, original pure Facts predicates, retained collection/journal/exit required; operational result recorded separately |
| UNKNOWN/timeout/journal/unconfirmed exit | Owned timeout/nonzero/stderr/invalid JSON, 11 incomplete journal cases, missing raw evidence, terminated/nonzero exit cases |
| Restart/cross-ID does not repeat side effect | Exclusive original-step claim and permanent supervised launch intent; concurrent native replay test |
| Marker/restore unavailable | Only seq04 accepted, fixed compare-only generated entry; orchestration executes one comparator and returns STOP05 |
| Publication interruption preserves old chain | Native staged no-replace publication fault tests, provisional ACK and mandatory root normal-exit witness |
| No Agent runtime change | Full branch diff contains only canary tooling/tests/docs; runtime/installer/provider unchanged |

Additional review regressions: incomplete journal/retained evidence and ACK-alone
acceptance first reproduced RED, then refused GREEN. Full synthetic loader
publication reproduced the refactor's `NameError`, then passed using the verified
prefix root. Callback budget consumption reached forbidden mocked process
creation RED; the corrected final budget check refused before creation GREEN.
Final freshness now checks pre-parsed timestamps after slow predicates and the
receipt rechecks preflight at the actual workload dispatch timestamp.

## Independent review and live evidence

First review on `f9a60d3` was NOT PASS: four Important findings concerning journal
completeness, stale dispatch state, missing raw evidence bindings and terminal
publication. Second review on `ce3f6de` was NOT PASS: undefined historical-root
reference and final dispatch budget/freshness. Both reviews reported no Critical
findings and no deferred Minor findings; no VM operation occurred before them.
Final exact closure contains 44 execution entries and 2878 runtime files.

Final independent review of `ccfaa5956f5790cb7460c1fcec426aacc8c0fbbe` / bundle i
returned **SOURCE PASS**, Critical/Important/Minor **0/0/0**, with no deferred
findings. All 44 execution entries and 2878 runtime files were checked through
retained native handles. The reviewer independently checked the actual retained
checkpoint03 config with corrected/incorrect parent and changed boot settings.
Review SHA: `89a5263925a71e194bb9aa2de11db8cdb0f9ed35369f909700ab9256514812a6`.
Trust SHA: `508ee4357db90971751c9a04707630f36df55727ba1a3092297193be8345067f`.
Corrected bootstrap SHA:
`c5349e3070c449ce62bd7ea54c383144f3d37b832dd03598be19087465ecefa3`.
The reviewer created/reread only exclusive protected detached records and made
no target contact. This review does not authorize retry or prove live acceptance.

### Actual controlled attempt

The only launched operational bootstrap used reviewed implementation
`0a3106cee045b6564205615e205fc74d43ea6ab0`, bundle h. Its independent source
review SHA was `b7b6be8e89733dbebcb6e10e2581b52755de100ad1b0306c00fce10c8013ca1e`
and detached trust SHA was
`6af54d03104dfe7d860533bb9042703230fdab74633116e0f13dc8ec4e69dc48`.
That source PASS preceded all target contact. It did not prove VM acceptance.

| Initial read-only constituent | Retained result |
|---|---|
| Management state | UNKNOWN, exit 1, 5.625 seconds; stdout 0 bytes, stderr 1513 bytes |
| Provider observation | TRANSPORT_COMPLETE, exit 0, stderr empty |
| Guest native observation | TRANSPORT_COMPLETE, exit 0, stderr empty |
| Recovery inventory | TRANSPORT_COMPLETE, exit 0, stderr empty |
| Current-state wrapper | TRANSPORT_COMPLETE, exit 0, stderr empty |

The management traceback ended in original `validate_config` with
`ValueError: storage/network/firmware/boot options changed`. The supervisor
observed root exit 1 with complete retained streams, without a timeout, and
published UNKNOWN. Initial preflight never passed. No original seq04 dispatch
claim, watchdog preparation, comparator dispatch, execution evidence, receipt04,
or root-completion witness was created. The permanent local root-launch intent
and UNKNOWN remain intact. The supervisor's retained stderr SHA is
`4391ed0e3749f0ed7beaa4be39b9545551a446767ee97f1c71814ccab631b229`.

Read-only source inspection found a current/saved snapshot-parent distinction
missed by the earlier source review. The current VM at checkpoint03 must use
the plan snapshot as parent, as the original worker does; the saved snapshot
configuration keeps the earlier parent and remains checked by `saved_guard`.
Bundle h erroneously checked the current config against that earlier parent.
The reviewer independently reproduced both PASS with the correct parent and
the same refusal with h's parent against immutable accepted checkpoint03
config. The local correction is committed in
`ccfaa5956f5790cb7460c1fcec426aacc8c0fbbe`, changing only
`tools/canary/task13_continuation/management.py` and
`tests/tools/test_task13_continuation_reconciliation.py`.

The reviewer additionally checked the already retained current-state wrapper
offline. The unchanged original `validate_current` rejects it: two of fourteen
known-process records have `present=true`; all records have expected keys and
`error_type=None`. Transport COMPLETE/exit0 therefore did not prove quiescence
PASS. No identity, process origin or PID-reuse conclusion is inferred. This is
a safety-predicate refusal, not a predicate to weaken or a process to terminate.
Correcting the parent alone would not establish a passing preflight. The
reviewer confirmed provider/inventory predicates and basic guest bindings only
as of their retained timestamps; no fresh acceptance was performed.

The live config was not returned before this guard failed. The exact live
mismatch, a sole runtime RCA, and fresh live snapshot identity therefore remain
unproven. No VM config, snapshot, service, owner or baseline was changed to make
the gate pass. Original local history was verified intact afterward.

The user explicitly requires "отказ от автоматического повтора при UNKNOWN".
There was no second VM attempt. Corrected source bundle i is an offline review
artifact only: ID `b95f34a4-d4a9-4f12-9033-8cc5493e1d70`, closure
`d7859c632aa19cf342c89bd785e1195cfc180ff41e68f4bf4249c8bdaeff2b02`.
It has no launch claim, capsule or operational receipt. A separate reviewed
recovery/relaunch procedure is required before another attempt. Seq05, marker,
restore and fleet actions remain blocked.

## Decisions and costs

All implementation rulings are listed here, including skill deviations:

- The user's approved specification and no-further-confirmations instruction
  authorize inline implementation. Independent review remains mandatory. Cost
  if misapplied: authorization failure; execution must remain closed.
- The user's exact-source requirement overrides general skill advice against
  renewed review after fixes. Every execution-source change needs renewed PASS.
  Cost if skipped: execution from unreviewed bytes.
- Existing historical files retain inherited restrictive SYSTEM/Administrators
  ACLs. New artifacts use explicit protected ACLs and owner. No old ACL mutation.
  Cost if wrong: storage trust failure.
- Operator intent is bound to the actual latest app-session user message, not
  an implementation-written quote. Detached review trust comes from the separate
  reviewer. Cost if wrong: self-issued/unauthorized continuation.
- Preserve the private ledger and test/review evidence through acceptance despite
  generic skill cleanup advice. Cost if wrong: loss of the required audit trail.
- Installed System32 SSH and PowerShell have two Windows-servicing hardlinks.
  Permit only their exact native canonical paths with pinned bytes/link counts
  and retained deny-write/delete handles. All other artifacts require one link.
  Cost if wrong: transport substitution; artifact checks are not relaxed.
- Receipt and ACK are provisional until a reviewed local supervisor observes
  actual root normal exit after final authorization and durable publication.
  Independent review accepted persistence of this already-observed fact as local
  evidence persistence, without renewed target authority. Missing proof, expiry,
  crash or UNKNOWN precedence blocks acceptance. Cost if wrong: false terminal
  PASS after failed publication.

## Architecture, publication and remaining scope

GitNexus's committed baseline matched `9144a26`; the relevant canary impact query
reported low indexed impact. Dynamic generated source/dispatch relationships
were verified against source and tests rather than inferred from absent paths.
No published API or cross-repository contract changed. Helpdesk was not edited.
This branch is local; no push, PR, production deployment or service change.

Remaining Windows product acceptance includes Setup/AuthentiCode/provenance,
rollback/low-disk/identity and hard-reset cases. This continuation and its test
success do not establish those results, READY FOR FLEET or Task 13 completion.

## Atomic implementation commits

Each commit was inspected, checked with git diff --check and verified with its task checks. Full final source suite is reported above.

| Commit SHA / English Conventional Commit | Included files |
|---|---|
| b7db977e271a1332d0aca5e8352148947243591c — docs(canary): specify Task 13 continuation protocol | docs/superpowers/reports/2026-10-11-task-13-continuation-initial-audit.md, docs/superpowers/specs/2026-10-11-task-13-continuation-v1-design.md |
| beeaea8747615e57b949c155b9cf83760acde4b0 — docs(canary): audit retained Task 13 evidence bindings | docs/superpowers/reports/2026-10-11-task-13-retained-evidence-audit.md, docs/superpowers/specs/2026-10-11-task-13-continuation-v1-design.md |
| 0fef13ebc9a82dff0b1efdff86eb50442cd4eb38 — docs(canary): plan Task 13 continuation implementation | docs/superpowers/plans/2026-10-11-task-13-continuation-v1.md |
| 326e97cd7294dcbe84b11e098f8fc46f01f005cc — feat(canary): verify immutable Task 13 historical prefix | tests/tools/test_task13_continuation_history.py, tools/canary/task13_continuation/__init__.py, tools/canary/task13_continuation/codec.py, tools/canary/task13_continuation/history.py |
| 5bcc15239b0922f4ffd917b23b04b1f9a16c5c8f — feat(canary): authorize and persist Task 13 continuation | tests/tools/test_task13_continuation_authority.py, tools/canary/task13_continuation/authority.py, tools/canary/task13_continuation/storage.py, tools/canary/task13_continuation/windows.py |
| 75b0714a3ccf75ca0a4f06a25c0b687b4d541ab5 — feat(canary): seal corrected Task 13 comparator closure | tests/tools/test_task13_continuation_sources.py, tools/canary/Extract-Task13ContinuationAst.ps1, tools/canary/Write-Task13ContinuationJournal.ps1, tools/canary/task13_continuation/authority.py, tools/canary/task13_continuation/journal.py, tools/canary/task13_continuation/sources.py |
| 0af08d89dd2911ba3f51d763cb397cf55bebcff1 — feat(canary): validate canonical Task 13 continuation receipts | tests/tools/test_task13_continuation_receipt.py, tools/canary/task13_continuation/receipt.py, tools/canary/task13_continuation/reconciliation.py, tools/canary/task13_continuation/sources.py |
| 8dda80bd07eb4b0c92d2c2569953441a9d988fe4 — feat(canary): execute only reviewed Task 13 continuation seq04 | docs/architecture/task13-continuation-v1-operator.md, docs/superpowers/specs/2026-10-11-task-13-continuation-v1-design.md, tests/tools/test_task13_continuation_authority.py, tests/tools/test_task13_continuation_loader.py, tests/tools/test_task13_continuation_receipt.py, tests/tools/test_task13_continuation_reconciliation.py, tests/tools/test_task13_continuation_sources.py, tools/canary/Observe-Task13ContinuationGuest.ps1, tools/canary/Prepare-Task13ContinuationWatchdog.ps1, tools/canary/Read-Task13ContinuationEvidence.ps1, tools/canary/run_task13_continuation.py, tools/canary/task13_continuation/authority.py, tools/canary/task13_continuation/bundle.py, tools/canary/task13_continuation/history.py, tools/canary/task13_continuation/loader.py, tools/canary/task13_continuation/management.py, tools/canary/task13_continuation/operations.py, tools/canary/task13_continuation/permission.py, tools/canary/task13_continuation/receipt.py, tools/canary/task13_continuation/reconciliation.py, tools/canary/task13_continuation/sources.py, tools/canary/task13_continuation/transport.py, tools/canary/task13_continuation/windows.py |
| f9a60d3524768bed972b76c1ffcfa6960d035a63 — fix(canary): close isolated continuation transport runtime | docs/architecture/task13-continuation-v1-operator.md, tests/tools/test_task13_continuation_sources.py, tools/canary/task13_continuation/bundle.py, tools/canary/task13_continuation/operations.py |
| ce3f6dee48cb21ef4370594074423502e8f294cf — fix(canary): close continuation acceptance and finalization gates | docs/architecture/task13-continuation-v1-operator.md, tests/tools/task13_journal_fixture.py, tests/tools/test_task13_continuation_loader.py, tests/tools/test_task13_continuation_receipt.py, tests/tools/test_task13_continuation_reconciliation.py, tests/tools/test_task13_continuation_review_fixes.py, tests/tools/test_task13_continuation_sources.py, tools/canary/Write-Task13ContinuationJournal.ps1, tools/canary/task13_continuation/journal.py, tools/canary/task13_continuation/loader.py, tools/canary/task13_continuation/receipt.py, tools/canary/task13_continuation/sources.py, tools/canary/task13_continuation/supervisor.py, tools/canary/task13_continuation/transport.py, tools/canary/task13_continuation/windows.py |
| c693e006c3f59a8e3b8a08f4020b5154fc83c79e — fix(canary): retain historical root through seq04 publication | tests/tools/test_task13_continuation_loader.py, tools/canary/task13_continuation/loader.py |
| 0a3106cee045b6564205615e205fc74d43ea6ab0 — fix(canary): recheck dispatch budget and final state freshness | docs/architecture/task13-continuation-v1-operator.md, tests/tools/test_task13_continuation_loader.py, tests/tools/test_task13_continuation_reconciliation.py, tools/canary/task13_continuation/loader.py, tools/canary/task13_continuation/receipt.py, tools/canary/task13_continuation/reconciliation.py, tools/canary/task13_continuation/transport.py |
| ccfaa5956f5790cb7460c1fcec426aacc8c0fbbe — fix(canary): validate current VM against checkpoint snapshot parent | tests/tools/test_task13_continuation_reconciliation.py, tools/canary/task13_continuation/management.py |
