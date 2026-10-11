# Task 13 read-only recovery with retained historical UNKNOWN

**Canonical preflight: READ_ONLY_CANONICAL_PREFLIGHT_PASS. Seq04 eligibility: NO.**
The newly authorized scope completed one fresh read-only canonical reconciliation.
Historical RCA remains **UNKNOWN**. No seq04 comparator, receipt04, execution
capsule, watchdog or new launch/workload claim was created. The consumed claim was
retained as evidence, never removed or reused. No SSH service or foreign process
was stopped.

Baseline: `codex/task13-continuation-v1`,
`ab393919d6ad5c48a8b7627a41a5ced782389385`.
Implementation: `7b4bebc4b5af67770f5a0bcdd6de8bc81c1a7f71` —
`feat(canary): add diagnostic read-only recovery for retained UNKNOWN`.

## Diagnostics and admission

Native identity v2 retains API stage, immediate Win32 error, partial sample,
selected ErrorRecord fields, HRESULT/inner exception chain and caller context.
It records no command lines, TargetObject, invocation text or unrestricted
exception messages. Raw identities and security context remain protected locally.

`classify_identity` and `reference_registry` are unchanged. PID alone grants no
admission; original-active and incomplete/denied/racing identity still block.
Diagnostic fields cannot override classification. A retained partial native birth
does not convert an API failure to PID_REUSED or PROCESS_ABSENT.

The owned exited-process regression captures QueryFullProcessImageName FALSE,
native error31, RuntimeException HRESULT -2146233087, a signaled handle and partial
creation time while classification stays IDENTITY_UNKNOWN. This proves a possible
mechanism, **not** the missing historical API/error. The old RCA report and failed
UNKNOWN remain unchanged.

The new actual human request binds `readonly-unknown-recovery`. Both execution
entries and upgrades to execution permission refuse this scope. The fresh loader
retains 80 failed-attempt source/evidence files and the consumed claim; historical
plan/seal, receipts00–03, baseline, snapshot and source/runtime pins remain mandatory.
The canonical reconciliation still validates all eight constituents.

## RED to GREEN and independent review

- Initial new regressions:6 FAIL before implementation; new6+identity24+readonly5
  then35 PASS. Extended new module:19 PASS in20.19s.
- First full run:245 PASS/1 FAIL. The old pre-launch test assumed the actual claim
  was unconsumed; the guard correctly refused it. Only the test changed: assert
  refusal on the real consumed claim, then use an owned protected temporary prefix
  for the changed-evidence fixture. No guard mocking or claim owner borrowing.
- Final complete relevant suite: **246 PASS in174.66s**. Command:
  `python -B -m pytest (Get-ChildItem tests/tools/test_task13_continuation*.py).FullName
  tests/tools/test_task13_process_identity.py tests/tools/test_task13_msi_profile.py
  tests/tools/test_task13_watchdog.py -q`, with the retained historical root input.
- Independent reviewer:30 and17 tests PASS; complete diff and exact-package review
  **PASS**, no blockers or declined-to-judge items. Verified53 execution entries,
  2879 runtime files,80 retained recovery files and consumed claim.
- Review corrected the local outer wrapper to import protected package modules
  under `-I -S -B`, retain its separately reviewed bytes, and match the native child
  PID/birth to the persisted window. The working-copy wrapper was never launched.
- `git diff --check` PASS; implementation commit contained only12 scoped files.

## Fresh actual canonical preflight

One protected fixed reviewed wrapper invoked the pinned direct base interpreter
with `-I -S -B` and `bootstrap.py --observe-reviewed-guard`. No old launch claim
was used. The native parent observed child exit0, wait0, matching creation time,
complete streams and empty stderr. The persisted verdict matched stdout.

Window:2026-10-11T15:09:26.591207Z to15:29:26.591207Z, exactly1200 seconds.
Verdict checked:2026-10-11T15:09:39.112046Z.

| Canonical constituent | Actual transport | Exit / stderr |
| --- | --- | --- |
| Management VM/provider/checkpoint state | TRANSPORT_COMPLETE | 0 / empty |
| Provider identity/inventory | TRANSPORT_COMPLETE | 0 / empty |
| Guest VM identity/state | TRANSPORT_COMPLETE | 0 / empty |
| Guest inventory/baseline | TRANSPORT_COMPLETE | 0 / empty |
| Original current guard/leaf/marker/wrapper scan | TRANSPORT_COMPLETE | 0 / empty |
| Native/CIM process identity | TRANSPORT_COMPLETE | 0 / empty |
| Guest clock | TRANSPORT_COMPLETE | 0 / empty |
| Management clock | TRANSPORT_COMPLETE | 0 / empty |

Native identity counts:14 PROCESS_ABSENT,2 PID_REUSED,0 ORIGINAL_PROCESS_ACTIVE,
0 IDENTITY_UNKNOWN. The two occupied slots have stable later native identities;
their historical absence/creation chronology is unchanged. There is no process-name
exception. Original leaf/marker absence and wrapper scans still pass.

The canonical validator confirms VM/provider/checkpoint, baseline and snapshot
bindings, exact receipt prefix, original safety predicates, transport completeness,
fresh clocks/deadline and original/source/runtime pins. Offline replay at the
recorded canonical finish time also passed; it is not another VM observation.
Independent offline runtime audit **PASS** confirmed all eight raw constituents,
native root/window identity, complete streams, original history/source bindings and
unchanged consumed claim. No diagnostic failure was observed. The reviewer made
no additional VM contact.

Verdict explicitly records historical_rca=UNKNOWN, seq04_authorized=false,
seq04_dispatched=false, claims_consumed=false, consumed_claim_unchanged=true.
Original seq04 dispatch claim and receipt04 remain absent. This result grants
no separate execution authority and is not Windows comparator/fleet acceptance.

## Evidence pins

Raw protected evidence stays local in the new read-only recovery package.

| Artifact | SHA256 |
| --- | --- |
| Exact source/runtime closure | e5dafc8cf10fc47f8ab77c5defb617ae2f9168b036dcf6ce8310f42ce6821520 |
| Independent source review | b1597df44ee66096e5d6db13f34817f1bddbcaebe8acdd2ce484d07af48d4409 |
| Detached trust | d0828ba7137f9887ae1caa25bdd6f73e1200bb06fab15da053fbeb430e015da7 |
| Reviewed wrapper | 85c3f2adee4e655e0434fda4d271fb3f7ccac02652cabfe5ddacad69efcf9b77 |
| Independent wrapper review | a67e7615726f071952368f5021179f09472488ddbe86f0bd18544969602a8755 |
| Fresh read-only window | 6086c0b17cd794911d7f91f3437a47a393881710876551a2a07643805a5cb7c1 |
| Canonical preflight | 141aa1c332b335c0ce2564b8a533d9a9202a5b494430eb50f37586319ad53224 |
| Read-only verdict | 94038b51c40debe1167a39473abd391334501ef469a917f269ca53f9921a356b |
| Native outer observation | 60449290b0b2e6f0aca81241d4fc16b01b5e87d22bee57beadcd25b288509353 |
| Offline preservation replay | b4cd93b5035b043a6655ba60d1e4359e764463915e315bd634456a273de1e663 |
| Independent observation audit | 66163b66b648fbec44a3e39b80c25dd76196213dfcc964ef421963ef97164832 |
| Unchanged consumed claim | 8a1185254bc199ee4f081c2965f16fd24589b1a2fb50877ae02e4b8c784e1a6d |

## Implementation files

- `tools/canary/Observe-Task13ProcessIdentity.ps1`
- `tools/canary/task13_continuation/process_identity.py`
- `tools/canary/task13_continuation/readonly_recovery.py`
- `tools/canary/task13_continuation/permission.py`
- `tools/canary/task13_continuation/bundle.py`
- `tools/canary/task13_continuation/loader.py`
- `tools/canary/task13_continuation/readonly_gate.py`
- `tests/tools/test_task13_continuation_readonly_recovery.py`
- `tests/tools/test_task13_continuation_gate_admission.py`
- `tests/tools/test_task13_continuation_recovery.py`
- `docs/architecture/task13-continuation-v1-operator.md`
- `docs/superpowers/plans/2026-10-11-task-13-readonly-recovery.md`

No push, PR, seq04 or later acceptance step was performed.
