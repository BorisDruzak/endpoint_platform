# Task 13 UNKNOWN recovery and occupied-PID RCA

Date: 2026-10-11. Scope: a separately reviewed recovery procedure, one possible
seq04 repeat, then STOP_BEFORE_SEQ05. No service termination, reboot, VM change,
guard weakening, original receipt rewrite or product/fleet rollout is authorized
by this procedure.

## Proven RCA

The two occupied known-PID slots were absent with no observation errors in the
immutable accepted current observation at 2026-10-09T06:45:30.5166660Z. Their
currently observed native births are 06:48:09.1198880Z and 06:48:09.0903065Z on that
date, both inside the receipt03 start-after-snapshot bracket
06:47:46.566919Z–06:48:16.189832Z. Independent review reproduced the comparison.
Numeric PID reuse during the authorized VM start is proven; these are not surviving
historical processes from the pre-stop observation.

Fresh read-only identity evidence confirms both processes remain alive, are not
PowerShell, do not match executed wrapper hashes, and are not the observer. Repeated
CIM identity and retained native birth/live-handle checks agree. One image-path hash
independently identifies `sshd.exe`; the other image remains unidentified. No claim
about its role or safe termination is made.

The unchanged original guard tests absence of each of fourteen fixed PID numbers.
It does not exempt a number after reuse. Therefore numeric reuse explains
`present=true` but does not establish quiescence PASS. Killing either process to
clear the numeric predicate would exceed this procedure.

Protected diagnostic source SHA256:
`28fd902c993bcd908b61055a25d2530aca3397a5170c9837913e895aebdc0023`.
Protected raw diagnostic result SHA256:
`d1a947ccd286f0f18a190414364aa129b34bc50f26ce2e534218b5e9a96cdc59`.
Private PID values, paths, owners, topology and command identities remain outside Git.

## Recovery implementation

Commit `ff232abeb3c31f1a2c3bff694c98f122b76f7f47`:
`fix(canary): gate one recovery after preflight unknown`.

The fixed previous failure is admissible only as initial read-only preflight
UNKNOWN. The gate pins its previous source closure, original prefix, capsule and
native terminal witness, verifies all retained phases and refuses any watchdog,
dispatch, receipt or original seq04 claim. Its protected recovery record binds
66 prior execution/evidence files; execution retains native handles and verifies
the same bytes and phase exclusions again.

The Windows venv executable is a redirector: an independent owned probe reproduced
Popen PID differing from actual Python PID. The earlier native terminal witness
therefore proves launcher exit, not the capsule creator's identity. Recovery adds
a separate native same-host/boot/token check that the actual prior creator is gone,
with a protected retained observation and a fresh execution-time recheck. Access
denial, unknown birth or a live exact identity refuses admission. The earlier
UNKNOWN stays unchanged.

The new package pins the actual base interpreter executable and selects it directly
for the supervised child. A native owned-process test verifies Popen PID/birth
equal the actual authority creator and subsequent signaled exit. Existing successful
receipt/root-completion PID/birth equality is preserved.

Independent preliminary review found one further issue: a second preflight UNKNOWN
would otherwise permit another CID against the first failure. The correction creates
a permanent protected recovery-launch claim shared across CIDs before Popen, keyed
by the original seal/tip and prior closure, and binding the new CID/exact closure.
The child requires its existing owner claim. A consumed claim prevents preparing or
launching another recovery, including after preflight UNKNOWN. The original seq04
claim remains separately mandatory. Neither claim is deleted or recycled.

Actual operator permission is recaptured from the latest human app-session record.
Recovery does not patch the original expired executors, source predicates, plan,
receipts, VM configuration, runtime, installer or provider.

## Exact package and verification

- Continuation ID: `a72a475a-720c-48aa-9c2d-af1b6aba1cbb`.
- Source closure: `ed7ecdedab2e201c44a0351a178777d835693f0c32ba7395a08175612e7a112d`.
- Package: 46 execution entries and 2879 pinned runtime files; offline preparation.
- Actual latest human record SHA256: `67bff71ede8e3a863b4d376b5ade002a624730e277456f2e43d7dfe909fcf18e`.
- Focused recovery tests: 20 passed; reviewer independently repeated 20 passed.
- Full frozen suite: 160 passed in 139.14 seconds. Command: Python 3.12 `-B -m pytest`
  with all `tests/tools/test_task13_continuation*.py`,
  `tests/tools/test_task13_msi_profile.py` and `tests/tools/test_task13_watchdog.py`,
  using the retained original history fixture. Local complete log retained outside Git.
- Git diff checks rerun after correcting a documentation-only trailing blank line.
  The first commit shell continued past that whitespace warning; no execution source
  changed. Final documentation checks require exit-code success before committing.

The implementation commit includes the operator document, recovery spec/plan,
`tests/tools/test_task13_continuation_recovery.py`, and package modules `bundle.py`,
`loader.py`, `permission.py`, `recovery.py`, `supervisor.py`, `windows.py`.

## Independent review and actual gate outcome

Independent exact-source/procedure review: PASS, zero Critical/Important/Minor
findings, none declined to judge. All 46 execution, 2879 runtime and 66 prior evidence
files were verified under retained native handles; original bindings, actual human
authorization, current prior-creator termination and single recovery claim verified.

- Review SHA256: `5aee758f27fc356fb4002bee8cdee595a99252ca5094f76358efa2bb076c4501`.
- Detached trust SHA256: `8d280ce3d7ec467494bbb55076e0b5c3322d0795183a426c8d85b2c204d29247`.
- Bootstrap SHA256: `fc24616ded432fb85d9765593a61dc57f9e3c128b60de5e72d561ddbcfa3bf07`.
- Protected actual operator-request artifact SHA256:
  `78358273b6a4b9a89f466bc773e6757fafc57bcf5c9a16cd132458302c4ee573`.

After this PASS, one bounded read-only original current-guard observation was made
using the retained reviewed package. It completed with exit0, empty stderr and
complete scanning at 2026-10-11T11:56:17.131765Z. The unchanged original predicate
refused: two known PID slots occupied, both explicit diagnostic pair slots absent,
zero matching executed wrappers. No predicate or old record was edited.

- Protected raw current transport SHA256:
  `d6c0c42e7fa7bb3fe912fca4eeaae224c93b9804494e22eefe5cd2ddc85e5f6e`.
- Protected gate record SHA256:
  `ad5eb848200614b1e0249ec566fc18dd73b1a0c9f977aa4286bc59ad0011b536`.

**Operational decision: BLOCKED before seq04.** No new recovery-root launch, launch
claim, continuation capsule, watchdog preparation, workload claim or seq04 receipt
was created. The authorized single repeat remains unconsumed. Resume gate is not
reached; seq05–09 remain unexecuted. Independent source PASS does not override a
live guard refusal. The original UNKNOWN, original bytes and receipt00–03 remain
preserved. Task13 is incomplete and no fleet-readiness claim is made.

Independent offline post-observation verification confirmed raw/parsed transport,
source/review/closure hashes, exact reviewed original guard entry and its unchanged
refusal at the sealed predicate's line215. The occupied PID set matches the earlier
diagnosis; this original observation has no birth fields and does not independently
reconfirm births. The new root remains unlaunched and both permanent claims absent.

The final documentation commit contains this report, the completed plan's actual
BLOCKED branch and operator-document whitespace correction. Executable source and
the independently reviewed package remain unchanged.
