# Task 13 IDENTITY_UNKNOWN root-cause investigation

**Exact historical root cause: UNKNOWN. Separate seq04 eligibility: NO.**
Stage A completed through one independently reviewed read-only identity probe.
It did not reproduce the historical exception. Stages B–D remain blocked because
their prerequisite, determining the actual cause, was not achieved. No guard
behavior was changed, comparator dispatched or receipt04 created.

Baseline: `codex/task13-continuation-v1`,
`eeeda0d7933cc5dee7510e3bd4abb6690bce43ff`. The baseline was clean.

## Exact proven refusal

Historical reference slot10 (zero-based) has no saved original creation time.
Its numeric PID and pinned absence FILETIME are retained in the private reference
registry and investigation ledger. No original identity was reconstructed.

In `Observe-Task13ProcessIdentity.ps1`, the first `Sample` threw before returning:
first=null, second=null, retained-first result=null, error_type=RuntimeException.
`classify_identity` rejects the row at its `error_type is None` requirement;
`identity_admit` then rejects IDENTITY_UNKNOWN in the original current guard.
The root traceback confirms this refusal inside `validate_current`.

The old catch stores only `Exception.GetType().Name`. It discarded API stage,
partial sample, ErrorRecord, FullyQualifiedErrorId, HRESULT, InnerException and
native error. Those fields cannot be extracted from the saved failed results.
The historical guest token/privileges were not retained either.

The old original plan/seal, receipts00–03, baseline/snapshot, consumed recovery
launch claim, failed capsule/root transport and supervisor UNKNOWN remain intact.
The previous original seq04 dispatch claim, comparator intent and receipt04 remain
absent. A successful later observation cannot retroactively replace that UNKNOWN.

## Hypotheses and evidence

| Hypothesis | Evidence and limit |
| --- | --- |
| OpenProcess AccessDenied | A direct native error5 returns an UNKNOWN sample in this source, so it alone does not explain first=null. A subsequent API refusal is not excluded. |
| Process exits between calls / exited retained object | An owned naturally exited process reproduces first=null and RuntimeException while its parent retains the process handle. Its wait is signaled. This establishes the mechanism, not the historical VM event. |
| GetProcessTimes failure | Its literal throw can produce RuntimeException; the old error record cannot distinguish it. No corresponding error appeared in the new probe. |
| QueryFullProcessImageName failure | The owned exited-process experiment returns FALSE, Win32 error31 and the literal native image unavailable. No such error appeared in the one new VM probe. |
| PowerShell/.NET wrapping | The owned experiment establishes that a literal throw is wrapped as System.Management.Automation.RuntimeException, HRESULT -2146233087, with no inner exception. The type alone is not proof of CLR failure. |
| 25-second observation bound | The old transport lasted 2.609 seconds and later rows completed normally; the saved data does not support this explanation. |

The owned experiment used the exact instrumented observer on a child which exited
naturally. It stopped no foreign process. The diagnostic error record contains
FullyQualifiedErrorId/message_id `native image unavailable`, category OperationStopped,
reason RuntimeException, stage QueryFullProcessImageName, immediate native error31,
first handle wait0 and a partial native creation time. That record belongs to the
local experiment; it must not be presented as the old VM ErrorRecord.

The native API contract requires checking FALSE and immediately retrieving
GetLastError; the diagnostic preserves that information rather than inferring
an API from the exception wrapper. See Microsoft's
[QueryFullProcessImageName reference](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamea)
and [GetProcessHandleCount reference](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesshandlecount).

## One new read-only probe

A distinct protected diagnostic package was prepared offline. Independent review
checked the exact instrumentation, unchanged sample/UNKNOWN semantics, source and
runtime pins, strict SSH selector, actual new human request and local controller
security context. Only after PASS did one diagnostic SSH command run.

The package retains the failed package's pinned SSH configuration/selector and
matches controller host/boot/token/elevation. The guest command uses the same
NoProfile/NonInteractive PowerShell entry with no identity switching or elevation.
Its current caller context is retained privately: NTLM authentication, no
impersonation, administrator role true, 64-bit PowerShell5.1.26100.9444,
CLR4.0.30319.42000, requested process access0x101000 and 24 privilege records.
The previous guest token was not recorded, so historical token equality cannot be
claimed beyond the pinned unchanged SSH execution route.

Diagnostics add bounded stage, partial sample, immediate native error, exception
type/HRESULT/inner chain and selected ErrorRecord fields on failure. They exclude
command lines, TargetObject, invocation text and unrestricted exception messages.
The diagnostic schema explicitly grants no acceptance or execution authority.
A fresh diagnostic-started marker prevents a second probe. It is separate from,
and never restores or reuses, the historical consumed launch claim.

Observation UTC: **2026-10-11T14:36:48.3148412Z**.
Transport: **COMPLETE, exit0, empty stderr, 2.704 seconds**.
Classification from the pinned controller: **14 PROCESS_ABSENT, 2 PID_REUSED**.
All sixteen rows have error_type=null. Slot10 specifically has native error87 and
CIM count0 in both samples: PROCESS_ABSENT now. No exception/ErrorRecord/InnerException
exists in this new row. Its exact earlier exit time, earlier native creation time
and the old throwing API remain unavailable.

The original source/runtime were held and verified during the call. Historical
prefix and every original claim file were checked before/after; preservation PASS
was retained. There was no further VM contact or probe after this result.

## Verification, review and unmet gates

Independent offline investigation confirmed the exact old classifier/current
refusal and evidence loss. Independent source review approved one diagnostic only.
Final independent offline audit: **PASS** for exact raw/source binding, current
identity classification, history/claim preservation and the STOP decision.
It does not issue a canonical preflight or seq04 PASS and performed no VM contact.

Existing guard regressions were rerun:

```powershell
& $task13Python -B -m pytest tests/tools/test_task13_process_identity.py -q
```

Result: **24 passed in 2.52s**, covering reuse, original-active, API denial,
missing data, native/CIM projection, exit/restart races and absence, plus the owned
live native observer. No actual-cause RED→GREEN correction is claimed: no VM cause
was reproduced, so a speculative production correction was not written.

**New full canonical preflight: NOT RUN / BLOCKED.** Only the identity diagnostic
was performed. Fresh provider, VM checkpoint, all-eight-constituent reconciliation
and new source-package preflight PASS are absent. The diagnostic result is not
a substitute for those gates. Existing guards, historical UNKNOWN and the
consumed execution claim continue to block seq04.

Changed tracked files are this report and the investigation plan. The diagnostic
runner/instrumented script and raw context are private protected evidence; no
process identities, topology, credential-bearing inputs or diagnostic dumps are
added to tracked source. There is no guard-fix commit.

## Evidence SHA256

| Artifact | SHA256 |
| --- | --- |
| Historical failed identity envelope | 0f25479b4befc5b4e5b2791a01d8d7cdb836b2d3dc16ff943365016e6b018945 |
| Failed execution closure | ef34fc154470552e32221e882f587be2e330fe2243bb4e9b4e70023aff35b2db |
| Diagnostic source manifest | dc14dded7b1d1d17236f38fb7da1cff4dc7083a16cf619fbc44b0bef9bfee77e |
| Independent diagnostic review | 42aac8c9e2aa2e803240ce2688c0906bea7024b45f96617d75429f393d081667 |
| Diagnostic intent | 55ec818b6216f64c2875634c3fed9075330d6056d7cfe968a03815fc71a125bd |
| Diagnostic result | e1af8803be2fd02def7e1d3303e503eb84bf9bfcafbf2445593d88682e7fbdb2 |
| Diagnostic validity window | 7332cad4cbeccfd5c2c5793f02df6163487ebf6644aa3c512f3e7f3cd7618d1e |
| Diagnostic single-probe marker | b05b9a7181b21276852c013029c1f011e1178858f38cc91dcc135cda092088e1 |
| Historical/claim preservation record | 32f11d4510af1a06516a483603d1a0f586e71a87fe35d7f36e8a26f83f4adf43 |

This investigation establishes current absence and a plausible reproducible local
failure mechanism. It does not establish the old VM root cause or Task13 acceptance.
