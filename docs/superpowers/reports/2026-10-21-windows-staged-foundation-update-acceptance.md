# Staged Windows Foundation update acceptance

Status: **in progress; not accepted for production or fleet use**.

The source plan is `docs/superpowers/plans/2026-10-21-windows-staged-foundation-update.md`.
Only the dedicated disposable Windows guest is in scope. Historical artifacts,
snapshots and acceptance sequences remain unchanged.

## Rejected candidate 3.2.123

Runtime source: `5b9db8fecc8e9b7368a052a674af4504aa872b14`.
Clean build checkout: `bc7a97a8f87de5f157b06cca6b872dc37935f814`.
Exact-source [CI 39593369699](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39593369699)
passed: 4414 tests, 728 skips. Supported Windows source gates passed:
2167 tests, 3 skips. These results do not establish installed acceptance.

| Artifact | SHA-256 |
| --- | --- |
| Signed MSI | `128cb5e27da8185918343336f49b69e9f8ba1066fa8f176315b10b5a3a11b341` |
| Signed Setup | `709b1a074b8edcf561364ec80cbd8dc516a9dc441ca0e8d512b42347e53c104d` |

Both signatures were valid with timestamp certificates. The isolated WiX 4.0.6
toolchain used an explicit matching Util extension DLL; global tools were not
changed. Frozen artifacts and detailed private controller evidence are retained
outside the repository.

The first genuine update used Foundation 3.2.120 with independently installed
Core 3.2.121. Online preparation took 24.65 seconds (14.68 seconds inside the
preparation operation, 820 owner grants taking 2.93 seconds). The old Agent
remained running through `prepared`. The saved runtime contained 111 files;
all file IDs, sizes and hashes matched after publication. Thus this observed
promotion wrote zero payload bytes. This is not the required 2500+ legacy-file
benchmark. Controller-held private comparison confirmed all four enrollment
leaf states were preserved, including the absent origin override.

The server observed Core 3.2.123, but policy application returned
`BROWSER_POLICY_HELPER_UNAVAILABLE`. Trial did not accept the candidate. The
owner stopped its services, then compensation failed with installer result 21
(`MSI_EVIDENCE_FAILED`). The journal remained `trial`; neither successful
automatic rollback nor the performance targets were proven. In particular,
the observed WSS outage exceeded two minutes.

A separate failure snapshot preserves the rejected state. Subsequent explicit
diagnostic recovery attempts are not automatic-rollback acceptance. A frozen
read-only probe confirmed original data, media, Foundation and Core proofs,
and exposed the provenance request mismatch below. The original guest snapshot
was restored; its clock was corrected and Core 3.2.121 reconnected to the server.

## Corrective source work

- `cc5717699c47cd9d4b933b8a468dce0dbbabc450` adapts the data-capture request to
  the five-field provenance contract, converts actual PowerShell JSON service
  state objects to validated hashtables, and keeps completed compound history
  out of post-switch forward-recovery admission. Native settlement still
  requires the authenticated helper and actual MSI barrier.
- `b543bc321d386dcd2a76b4a8efed8d0774722948` avoids full runtime hashing inside
  every Browser Policy pipe request during trial. Verification is cached for
  one listener lifetime and exact immutable binding/selector; caller identity,
  protected selector security and allowed lifecycle phase are checked again
  for each request.

Regressions were observed failing before the fixes. The corrective selection
passed 68 tests. Actual repeat acceptance requires a newly frozen version;
3.2.123 media and its manifest will not be replaced.

## Rejected candidates 3.2.124 and 3.2.125

Candidate 3.2.124 used runtime source
`53833960231f7b09590f08268e710ecd6fa00ad4` and build checkout
`7205b2f1754272ffcf45f7183a6e5038855dc20a`.
[CI 39605557200](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39605557200)
passed 4433 tests with 738 skips; Windows passed 2195 tests with 3 skips.
Its genuine 3.2.79 run was stopped for performance investigation before
switching. The original Agent remained running. A saved failure snapshot and
the explicit test-VM reset do not establish automatic rollback.

On that VM, 20 native feature-state queries took 1.725 seconds. The genuine
predecessor has 2557 components sharing one feature. Commit
`441d6135e7a34612a57a50ab559e8d9ee105aa47` checks each unique feature before
and after the complete component walk, retaining every live component/keypath
check and rejecting feature drift. The targeted selection passed 130 tests.

Candidate 3.2.125 used runtime source
`e4f49949c5c67658a0826d653c742611b3eb9794` and build checkout
`3beb016abd33b3a17cdd1bb862de64b30efedb26`.
[CI 39612016714](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39612016714)
passed 4437 tests with 738 skips. A complete Windows repeat passed 2198 tests
with 3 skips. The first Windows attempt had one failure in the unchanged
system/process capability test; its isolated repeat and the complete repeat
passed, without suppressing or modifying that test. Both MSI and Setup had
valid signatures and timestamp certificates.

| Artifact | SHA-256 |
| --- | --- |
| 3.2.124 signed MSI | `b1ff4d778d2327bf801c13c1c6599b78c8049ed7eee38139f7f15cc927652945` |
| 3.2.124 signed Setup | `38892e8ee677c8b940cd36096dc86513d99a15a6a4d53cf70cca1ace8676eca0` |
| 3.2.125 signed MSI | `7e18cb2278d3fb6662c50c86ce33fef9413f118afba5c35441fcfde9892fd64c` |
| 3.2.125 signed Setup | `d3e1bc46906750a8d8b1150917e69b31e5404bf2262d166998e762b6f5d13862` |

In the genuine 3.2.79 run, all 2543 retained files (48,313,190 bytes) were
captured. The old Agent remained running through `prepared` at 14:08:47 UTC.
Its connection closed at 14:09:02; the new native registration appeared at
14:12:18 and the new Agent was running at 14:14:17. The server observed
3.2.125 and a fresh APPLIED policy ACK at approximately 14:14:26. These
observations fail the two-minute outage target and do not establish acceptance
within ten minutes. The large before-file-ID response exceeded the private
transport's output bound, so full legacy zero-copy file-ID acceptance remains
incomplete; the transport guard was preserved.

The genuine predecessor had no `updates` directory. Consequently the candidate
could not publish its trial proof, despite successful WSS/policy operation.
Timeout automatically entered `rolling-back`, but candidate-removal preflight
requested a directory-flush mutation forbidden by the owner's read-only
preflight policy. A separate timeout path called `win32file.CancelIoEx`, which
is absent in the pinned pywin32 311. Uncaught helper exceptions left hidden
windowed error dialogs and stalled the native transaction. This is a failed
automatic-rollback attempt, not successful rollback evidence.

The failed RAM state was preserved. Before the controlled reset, all four
private enrollment leaf states still matched their controller-held baseline.
The VM was restored to the original healthy 3.2.79 snapshot and reconnected.

Corrective commits:

- `cf2f7f2c66511c79376b88d9cf39fa0f675aca92` creates the missing proof directory
  under the authenticated quiescent owner, with canonical update ACLs and
  trusted-parent validation.
- `83756082995c361c76970319e96dbd3f4af030ff` creates rollback child directories
  only in `prepare`, validates them without mutation in native callbacks,
  cancels the caller thread's pending pipe I/O using the available API, and
  returns failure for unexpected installer-helper exceptions instead of
  entering a windowed dialog.

The corresponding regressions failed before the fixes. The combined targeted
selection passed 172 tests, including a real pending Windows pipe cancellation.
Candidate 3.2.126 is frozen from
`217ff3569a28900f7723197c2057738751d3e5ad`. Its subsequent actual test is
reported below; no performance or automatic rollback pass is claimed.

## Actual 3.2.126 early-crash attempt

The clean build checkout was
`e00b16d6b722f248c5b38ae45d10375103a6e0e3`. The Windows gate passed
2209 tests with 3 skips; exact CI run 39626585773 passed 4445 tests with
739 skips. MSI and Setup signatures and timestamps were valid. All 171
frozen product sources matched; fixed-entrypoint and Setup source closures
contained only this checkout's project modules.

The genuine 3.2.79 attempt prepared online from 15:42:04 to 15:45:26 UTC.
The original Agent stayed running during preparation. A complete receipt
captured NTFS IDs, sizes and hashes for 2543 retained files (48,313,190 bytes).
This before-only receipt does not prove an ordinary-success promotion or
zero restore bytes.

The old Agent stopped at 15:45:41. Candidate registration appeared at
15:48:59, and the trial began at 15:50:53. Candidate WSS and a fresh APPLIED
policy ACK were observed at 15:51:13. The previously missing proof directory
was created successfully; the local proof recorded connection and policy
application. The exact candidate process was then deliberately terminated
after its executable hash was checked. No trial heartbeat or acceptance
was established before termination.

The owner automatically entered `rolling-back` at 15:51:55. Native candidate
removal reached preflight, then Windows Installer event 11722 identified
`InstallerOwnerEnter` failure at 15:56:02. The removal transaction aborted and
candidate registration returned. Setup reported `INSTALL_FAILED`, exit 21,
`MSI_EVIDENCE_FAILED`; the child fence remained `msi-starting`. This localizes
the failing action but does not establish its underlying exception or cause.
Neither restored original Foundation/Core nor completed automatic rollback
was proved. Both performance targets had already been exceeded before the
injected fault.

The four private enrollment leaves still matched. Snapshot
`staged126-rollback-20261021`, signed artifacts and case evidence were preserved.
The dedicated guest was manually reset to its own healthy 3.2.79 baseline;
fresh original WSS and policy application were subsequently verified. This
fixture reset is not automatic rollback evidence.

The subsequent source correction adds bounded Application event diagnostics for
native-helper failures: phase, known error code, error type, native error
number and locations in project code. It excludes exception messages,
arguments, locals, absolute paths and session identifiers. Event delivery
cannot change installer completion authority or failure exit codes. Its
signed installed validation and the underlying native failure correction
remain pending.

## Actual 3.2.127 diagnostic attempt

Runtime source was `58f70d3b8bf8fd7199382e0e9ae1882457929a2a`, clean build
checkout `76497e875a2725658cd0cfa1f4dc2610407af73d`. Windows passed 2220 tests
with 3 skips; exact CI 39635683080 passed 4457 tests with 739 skips. Signatures,
timestamps, all 172 source files and fixed-entrypoint/Setup closures were checked.

On genuine Foundation 3.2.120 with Core 3.2.121, preparation ran online from
16:50:36 to 16:50:50 UTC; all 111 retained file IDs/hashes were captured. The old
Agent stopped at 16:50:57. Trial began at 16:54:23 and the candidate was running
at 16:54:33. The exact candidate was deliberately terminated after hash
verification, before a fresh candidate WSS/proof was established. The owner
entered `rolling-back` at 16:55:00. Windows Installer event 11722 again identified
`InstallerOwnerEnter`, at 16:55:50. Native removal aborted, candidate registration
returned, and Setup exited 21. The four private leaves still matched. Snapshot
`staged127-rollback-20261021` and immutable artifacts/case evidence were preserved.
Automatic rollback and the two-minute interruption target did not pass.

No new diagnostic event was emitted. Inspection of the actual frozen service
archive confirmed that the diagnostic module was included, but its script entry
used a level-1 relative import. PyInstaller starts this entry as `__main__` without
a package. A regression reproduced the missing report with that exact module
context. The correction uses an absolute import; 58 selected tests passed. Before
another native update, a controlled denied invocation of the actual newly built
helper must prove event delivery. This corrects diagnostic visibility; the
underlying native action failure is still unresolved.

## Actual 3.2.128 automatic rollback

Runtime source is `e987bbd27ac7e10b3dce3392b6b21e3d38dac591`; build checkout
is `9be8d675cb332a228db64395c700d6be5640770c`. The complete supported Windows
selection passed 2235 tests with 3 skips. Exact-source
[CI 39645604507](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39645604507)
passed 4473 tests with 739 skips. All 172 frozen source records, project-module
closures, MSI/Setup signatures and timestamps were checked.

| Artifact | SHA-256 |
| --- | --- |
| Signed MSI | `60ab22e0030db5d019b531e8acbae1f87317823bf1a67114c06f1f269fa2b556` |
| Signed Setup | `1c61fc89697d84268e356d9438761483777a83866a7fa6515dd56b28ee849259` |
| Core ZIP | `66936f226d86e9dcd1476a414fd6bbf617b56292cb34e1e51e8a873ea471c1c1` |

The actual frozen helper contains the diagnostic module and its absolute
level-0 entrypoint import. A controlled invocation without installer authority
exited 1 and emitted the expected bounded Application event 1001. The helper
hash matched `Binary.EndpointInstallerHost` extracted read-only from the signed
MSI. The private smoke harness initially required a separate helper signature
and stopped before execution; this was corrected to the project's signed
container binding without changing frozen artifacts or admission checks.

On genuine Foundation 3.2.120 with Core 3.2.121, observed online preparation
ran from 17:52:35.576 to 17:52:53.740 UTC while the old service ran. All 111
retained MSI Core files (39,686,091 bytes) kept identical NTFS IDs, sizes and
hashes after publication, proving zero second-copy payload bytes for this tree.
The old Agent stopped at 17:52:57.217; the candidate was running at
17:56:45.049. This approximately 228-second service interruption already fails
the 120-second bound, independently of the subsequent injected fault.

The controller deliberately terminated the exact candidate process after
verifying its executable hash. The owner entered `rolling-back` at 17:57:07.130.
Candidate registration disappeared at 17:57:49.981, the original MSI returned
at 17:58:48.226, and strict native/Core/data verification completed before
`rolled-back` at 17:59:33.990. Setup exited 67 at 17:59:37.650, approximately
502 seconds after launch; both Agent and Browser Policy services were running.
The original Core 3.2.121 selector and source revision were restored. At
18:00:43, the server confirmed its open WSS session with a fresh heartbeat and
matching `APPLIED` policy ACK. All four private enrollment leaves matched.

This is a completed automatic rollback on the observed modern baseline. No VM
reset produced this result. A separate snapshot and immutable case evidence
preserve it. The native entry correction validates the removal role's captured
maintenance authority after product unpublication; the authenticated staged
removal flag preserves original Core trees from recursive candidate cleanup.
Normal uninstall cleanup and all other roles retain their existing checks.

## Actual 3.2.128 ordinary update

A separate ordinary run started from the original Foundation 3.2.120 / Core
3.2.121 guest snapshot, after the completed rollback evidence was preserved.
The same signed 3.2.128 artifacts passed a fresh baseline/private-data/WSS check.
Setup ran from 18:08:41.729 to 18:15:23.009 UTC and exited 0: approximately
401.28 seconds. The journal reached `accepted`; the selected Core and native
product were 3.2.128. The server confirmed the new version, matching `APPLIED`
ACK at 18:13:59.839 and fresh heartbeat at 18:14:59.819. Both services ran and
all four private enrollment leaves matched. A separate snapshot preserves this
successful installed state. These facts establish the observed ordinary update,
not the remaining predecessor/fault matrix.

The observed service interruption was 212.08 seconds, from 18:10:23.030 to
18:13:55.106; the new WSS/ACK followed service startup. The total run meets the
600-second bound, while the 120-second reconnection bound fails. No identical
cold/warm pair is claimed. Cached watchdog processes were still observed after
acceptance, although the journal's original owner had exited; their termination
and the owner-loss/reboot scenarios remain to be verified.

A private read-only tool subsequently measured the same project's installed
MSI inspection routines on the guest. Three reads of the exact expected package
took 0.725, 0.657 and 0.665 seconds. Native registration verification took
0.190 seconds, pinned Foundation byte verification 0.671 seconds, and complete
installed Core inspection 2.651 seconds. The tool's 55 project modules were
checked against this checkout. It granted no installer authority and modified
no installed state. These isolated measurements do not explain the full
interruption or justify removing validation; native phase timing investigation
remains open.

## Actual 3.2.79 to 3.2.128 update

The genuine 3.2.79 baseline passed a separate ordinary update using the same
signed 3.2.128 artifacts. Observed preparation ran from 18:37:03.142 to
18:40:31.392 UTC while the original Agent and Browser Policy services ran.
The complete retained inventory contained 2543 files, 48,313,190 bytes. At trial,
every NTFS file ID, size and hash matched after publication. This proves zero
second-copy promotion bytes for the full legacy payload, rather than a sample.

The old Agent stopped at 18:40:45.411 and the candidate ran at 18:46:06.993,
an observed interruption of approximately 321.58 seconds. New Core 3.2.128
connected and acknowledged its matching policy at 18:46:12.239. The journal
reached `accepted` at 18:47:19.774. Setup exited 0 at 18:47:25.066, approximately
757.53 seconds after launch; native product and selected Core were 3.2.128,
services ran and all four private enrollment leaves matched. Both performance
bounds fail on this predecessor despite the completed functional update.

Native logging policy was saved before the diagnostic run and restored in its
controller's `finally` block. Private logs contained only the bootstrap costing
sessions: their `CostFinalize` actions took four and two seconds. They did not
capture the subsequent native transaction's actions. They therefore do not
establish the remaining delay's cause or justify changing validation/rollback.

The live cached recovery Setup processes remained after terminal acceptance,
with the original owner gone, the scheduled task retired and no child recovery
PowerShell. The actual frozen Setup entry contains two level-1 imports in
`_run_staged_recovery`; the first precedes its exception handler. Five real
file-entry regressions reproduced `ImportError` without a parent package.
Both imports were corrected to absolute imports inside the bounded handler;
101 related tests passed. This is a source correction, not installed recovery
acceptance. The next frozen candidate must prove bounded Setup recovery entry
and actual owner-loss/reboot behavior before admission.

## Remaining admission

Ordinary success on plain 3.2.120, all no-proof rollback cases,
early-crash rollback on genuine 3.2.79 and plain 3.2.120, identical-baseline cold/warm measurements,
the interruption performance bound, reboot and remaining fault matrix are
pending. The report verifier
withholds a complete pass when a scenario, native Foundation/Core proof,
private preservation check or measured performance target is missing.
