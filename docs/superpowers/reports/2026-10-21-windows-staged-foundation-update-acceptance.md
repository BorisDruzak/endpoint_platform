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

## Actual 3.2.129 recovery entry and owner loss

Runtime source is `09aff5164decb42542b443cdaa7f7ddbc0eb2376`, build checkout
`5df252134b1b272b1f7feb204252fb4ed19a78c9`. The full supported Windows selection
passed 2240 tests with 3 skips; exact
[CI 39658935741](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39658935741)
passed 4479 tests with 739 skips. Frozen source records, project-module closures,
MSI/Setup signatures and timestamps were checked.

| Artifact | SHA-256 |
| --- | --- |
| Signed MSI | `ad88341a622da22d1c780ec89784019c542300cd587de067d61b9e222fbaa207` |
| Signed Setup | `d3641a3600740e96881cdfd4aca7a3392948675dd22042382d9203f15075fd29` |
| Core ZIP | `2435d277a381a65f4a0eb03543847899c4300ae5daf33c331b9ccdec0494ca1d` |

Inspection of the actual Setup CArchive proved both recovery imports at level 0
and both dependency modules present. On a genuine plain 3.2.120 baseline, its
recovery CLI without an operation journal returned the expected denial 60,
created no journal and left no processes. The full invocation took 111.03
seconds, including the intentional 60-second missing-journal wait and startup.
The actual MSI helper also rejected a missing capability and emitted the bounded
diagnostic event. All four private leaves remained equal across these probes.

For the live owner-loss case, the controller verified the operation, prepared
phase, owner PID, creation time and canonical PowerShell image hash before
terminating only that owner. The parent Setup exited 21 at 19:25:24 UTC as a
result of this injected failure. The scheduled cached recovery Setup then
completed cancellation automatically: `rolled-back` was observed at 19:26:14,
with original native/Core 3.2.120, running services, fresh WSS and matching
`APPLIED` policy. All four private leaves matched. At 19:27:23 the recovery
task was absent and no Setup/recovery processes remained. A separate snapshot
preserves this state.

This proves recovery after prepared-owner termination, before native product
replacement. It does not prove recovery after interruption of a native
transaction or guest restart during promotion.

The first retry's private harness incorrectly treated any `msiexec` process as
an active owner. Fresh inspection showed no fence or Setup process and ample
capacity. The exact hash-verified owner program's real empty native Begin/End
barrier then succeeded without product scripts. Only this harness classification
was corrected; the signed installer still performs its full ownership admission.
The separate no-proof timeout/retry case completed as recorded below.

## Actual 3.2.129 no-proof timeout rollback

A retry on the recovered plain 3.2.120 host used the same signed 3.2.129
artifacts. A scoped firewall rule blocked only the candidate Core executable's
outbound traffic. The original service remained connected during preparation;
the new native product was installed and trial began at 19:38:16 UTC. The
candidate service ran at 19:38:37, but no fresh candidate WSS/proof was obtained.
It was not accepted. After the bounded trial, the owner stopped its services and
entered `rolling-back` at 19:41:28 without any further controller action.

Candidate registration disappeared at 19:42:12, the original MSI returned at
19:43:07, and strict rollback verification completed before `rolled-back` at
19:44:00. Setup exited 67 at 19:44:04; the original native/Core 3.2.120 and source
revision were restored and both services ran. All four private leaves matched.
At 19:44:44 the server confirmed original Core 3.2.120, an open WSS session,
fresh heartbeat and matching `APPLIED` ACK. The fault firewall rule was removed.
At 19:46:20 the recovery task and all Setup/recovery processes were absent.

This is a completed automatic Foundation/Core rollback after actual candidate
installation and missing health proof. It is distinct from prepared cancellation
and the earlier 3.2.128 early-crash rollback on Core 3.2.121. The timeout case's
629.70-second total includes its deliberate 180-second failed trial; it is not
an ordinary-success performance measurement. Its observed service-start pause
already exceeded the 120-second goal. No full matrix or performance pass follows
from these successful individual recovery cases.

## 3.2.130: pinned MSI reads and measured modern success

Runtime source is `88304d9b9975f1e370bd5d33d939a817db2abefc`; the clean build
checkout is `cf3c88113594f1beceddf1775393e7b863b62c9a`. Source change
`06bde90e1ac380558654a8aeeddcc8235c2b6754` reuses fully verified MSI inventories
only within an authenticated helper phase and while native handles deny writes
and deletion. Every mutation first checks the live owner, then releases the
handles and invalidates reuse. Installed native state, SCM, ACL, payload and
health checks retain fresh observations. Independent returned objects prevent
manifest mutation from affecting subsequent checks. Nine Windows pin tests
cover replacement, deletion, writers, identity/phase separation and mutation
invalidation. The related suite passed 430 tests. A separate test-fixture import
order defect was reproduced and fixed in
`318379dc396e77a618c1df4959e2432e08f552d4`; its two suites passed 124 tests.

The complete Windows gate passed **2249 tests, 3 skipped** in 286.34 seconds.
[CI 39709199721](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39709199721)
on the exact build checkout passed **4480 tests, 748 skipped** in 245.38 seconds.
Contracts, compilation and whitespace checks passed. All 172 pinned source
hashes and fixed entrypoint closures match this worktree. The 722-file raw Core
tree is `845890a477220ac5ae1b4abb2ad2bd38f5710f8a61aaf854a8330982d99e3b16`.

| Artifact | SHA256 | Bytes |
| --- | --- | ---: |
| MSI | `e66401d5a600b130867dec1414c1869a698f78844fae01af45607c30eb5a4c8c` | 173043712 |
| Setup | `19f6368d39a7964a00ccc1e904802d3aab9a126e708134557ca806471af21dfa` | 191818704 |
| Core ZIP | `9c3da0a2ff62d715ab764bcc9f9fe3d856b3348e26dd36a16df459406ea1b51d` | 22892978 |

MSI and Setup signatures and timestamps are valid with the existing approved
signer. The helper is exactly `Binary.EndpointInstallerHost` from that signed
MSI, SHA256 `474936360433bc70a03ab6db9f910e65b4d97a2c7cc621db79c4ff3293346a4b`.
Actual frozen inspection confirms qualified imports and recovery modules.
The real helper denied a missing capability with exit 1 and its bounded event;
all four private leaves matched before and after this smoke check.

Read-only measurements on the dedicated Windows guest found a denied frozen
helper takes 2.98–4.12 seconds to start and exit. Inspecting the installed
legacy tree took 10.08 seconds, versus 2.65 seconds for the modern tree.
An instrumented read-only validation repeated every original check: the legacy
inspection took 9.40 seconds, including two full legacy payload walks totaling
3.77 seconds and 2554 protected-state ACL validations totaling 2.20 seconds.
Eight reads of the exact signed MSI took 5.69 seconds without reuse and 0.94
seconds with pinned reuse. These measurements establish individual costs;
they are not installed-update performance acceptance.

Case `modern121-success-cold130-01` restored the same original Foundation
3.2.120 / OTA Core 3.2.121 guest snapshot used for the earlier modern test.
The clock and baseline WSS/APPLIED state were refreshed before staging. On
2026-10-22 UTC, Setup ran **02:15:24.213–02:21:55.179**, exited 0 and accepted
the candidate after actual new WSS, heartbeat and matching policy proof.
Online preparation completed while the original agent ran. The observed stop
at **02:17:02.964** and new running service at **02:20:24.999** give a
**202.04-second service pause**. First observed new WSS was **207.36 seconds**
after the stop. Total **390.97 seconds** passes the 600-second ordinary-success
bound; the **120-second interruption bound still fails**. The earlier modern
3.2.128 test measured 212.08 seconds to service startup; this comparison is not
an identical-baseline cold/warm pair or a completed performance acceptance.

All 111 retained files, 39,686,091 bytes, kept their NTFS IDs, sizes and hashes
through publication. The native product, current Core and source revision are
3.2.130 / the runtime source above. Four private leaves remain byte-identical.
At 02:25:34 UTC the server confirmed fresh 3.2.130 WSS and matching APPLIED
policy. At 02:26:54 the recovery task and all Setup/helper processes were absent.
Snapshot `staged130-modern-success-ok-22` preserves this result. No production
or fleet publication occurred. Further optimization and the full fault matrix
remain required.

A separate throwaway, read-only frozen self-launch diagnostic on this guest
used PyInstaller 6.22.3 with forced onefile-parent verification and the helper's
project import graph. Four fresh executable launches took 5.35 / 3.07 / 2.93 /
2.75 seconds. Four separate worker processes launched by the already initialized
same executable took 0.193 / 0.173 / 0.176 / 0.169 seconds and reused the same
extraction root. The agent remained running. This establishes a supported
initialization optimization to investigate; it grants no installer authority
and does not establish packaged update, rollback or interruption acceptance.

## Candidate 3.2.131: preinitialized phase workers, performance still FAIL

`b341ccade9caebb646c51a3875f92ba90dad992d` adds the launch-only broker,
fixed-helper entrypoint and PowerShell routing, with source/PowerShell tests and
README/CODEMAP updates. Each phase keeps its independent process and original
HMAC/mutation authorization. Before reuse, the private bootstrap extraction is
hardened to SYSTEM/Administrators and pinned against writes/deletion/rename;
every launch checks its namespace, identities and current security descriptors.
The launch channel grants no native authority. Server and Gateway contracts are
unchanged. The MSI phase-read budget fallback is included from
`42d7eaeba2aee15b94da44bad3cd7a3fc70a085f`.

Frozen runtime source: `f520fa0ee67993c1b40770e7c5c98504459f7879`; approved
manifest commit: `3984a41e7a933646be2870d9338471d69dac7fcf`; build/source-gate
checkout: `c19692b45e2cb8c7cf003be5d88fe895f10ca743`. The latter changes only
an extracted-wrapper fixture to load the real null-launcher cleanup function;
the original failure was observed in both Windows and CI. After correction,
Windows passed 2293 tests with 3 skips (291.74 seconds), and exact-head
[CI 39718280882](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39718280882)
passed 4499 with 774 skips (351.45 seconds). Contracts, compileall and whitespace
checks passed. All 173 normalized runtime sources and fixed-entrypoint project
closures were checked against this checkout. Existing artifacts remain immutable.

| Artifact | SHA-256 |
| --- | --- |
| Signed/timestamped MSI | `3998c53f675fdb325912319eef5cad797efba2c0b0ce304a9e83b049f04729d7` |
| Signed/timestamped Setup | `47f042685ce06fe7946436741883bdd10579cbd7bfd1d09bfc7573084a4c0e70` |
| Core ZIP | `d43d01c998382e54a1f868258f067dbaa4faa1fcf38e324642d0bd5f0f480a89` |

The fixed helper (`3033321d9a9b9daca5613f686ccd7e89aacbcfd2c90af9c366e54e565b6dffc3`)
was matched to `Binary.EndpointInstallerHost` read from the signed MSI. Actual
frozen inspect and launcher invocations without a capability both exited 1 with
bounded diagnostics and no dialog. Frozen recovery imports were verified; this
is not yet an installed 3.2.131 owner-loss or reboot result.

On the same original Foundation 3.2.120 / OTA Core 3.2.121 fixture, ordinary
Setup ran from 03:53:12.390 to 03:59:37.579 UTC on 2026-10-22, exit 0
(385.19 seconds). Preparation was observed at 03:54:33.002 and prepared at
03:54:51.758 with the original Agent running. Old Agent stopped was first
observed at 03:55:06.984; new service Running at 03:57:57.691: **170.71 seconds**.
Fresh new server WSS was established at 03:58:17.967: **190.98 seconds** after
the observed stop, still above 120 seconds. Matching APPLIED policy was confirmed
at 03:58:18.074, followed by the unchanged stable-health acceptance. Accepted was
observed at 03:59:24.331. All four private leaves matched. All 111 retained
Foundation payload files (39,686,091 bytes) kept identical NTFS IDs, hashes and
sizes through promotion. At 04:01:48, the recovery task and all Setup/helper
processes were absent. The success fixture was preserved separately.

The service pause improved from the preceding observed 202.04 seconds, while
stop-to-WSS improved from 207.36 to 190.98 seconds. These are separate candidate
observations, not a completed cold/warm pair. A protected read-only frozen probe
measured complete hardened-runtime checking plus same-executable startup at
0.58–0.61 seconds versus 3.03–3.58 seconds cold; initial hardening took 3.61
seconds before old-agent stop. This supports the implemented mechanism, without
establishing the remaining performance or fault matrix.

Remaining delay is still under investigation. In this run, Core creation followed
observed SCM Running by 15.8 seconds; a later read-only full launch-validation
probe took 2.60 / 1.97 / 2.01 seconds, so it does not establish the cause of that
critical-path interval. Full SHA-256 on the same pinned 173 MB MSI took about
0.92–1.16 seconds with the default framework implementation and 0.94–0.96 with
CNG; no algorithm change was justified. Native action-level timing and the
3.2.131 rollback/fault acceptance remain outstanding. No checks, native barriers,
health windows or rollback criteria were reduced, and nothing was published to
production or the fleet.

## Remaining admission

Ordinary success on plain 3.2.120, no-proof rollback on genuine 3.2.79 and Core 3.2.121,
early-crash rollback on genuine 3.2.79 and plain 3.2.120, identical-baseline cold/warm measurements,
the interruption performance bound, reboot and remaining fault matrix are
pending. The report verifier
withholds a complete pass when a scenario, native Foundation/Core proof,
private preservation check or measured performance target is missing.

## Additional 3.2.131 rollback evidence (2026-10-22)

On the original Foundation 3.2.120 / OTA Core 3.2.121 fixture, the candidate
Core was deliberately terminated during its real health trial. The owner
automatically entered rollback at 04:23:03 UTC. Candidate registration
disappeared, native Foundation 3.2.120 returned, and the journal reached
`rolled-back` at 04:25:21.485. Setup exited 67 at 04:25:26.635. Original
Core 3.2.121, all four private leaves, fresh original-version WSS at
04:25:26.815 and its matching APPLIED policy acknowledgement were verified.
This was actual native compensation, not a fixture restore.

Terminal companion cleanup initially failed a strict post-use Foundation-byte
identity check. Its cause remains unproven. The unchanged scheduled recovery
task and signed cached Setup completed cleanup on an explicitly requested
supported retry; that retry was manual. Do not describe this as fully automatic
3.2.131 cleanup. Source `e94a4add68a3e92b943dba1da9a5a92320403fa2`
adds at most three automatic retries one minute apart, with fresh owner/native
proof and unchanged byte/identity checks.

## 3.2.132 incoming-Core preparation attempt (2026-10-22)

Runtime source `5d942d78d4c47b908ae8457c4ed56a881102f5f7` and build
checkout `792470535a7ce2ed144515a4da113d6ca3762222` introduce an internal
Core archive bound to the signed MSI inventory. Full Windows selection passed
2318 tests with 3 skips (290.09 seconds).
[CI 39729059884](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39729059884)
passed 4519 with 780 skips (320.45 seconds). All 174 normalized project sources,
fixed-entrypoint closures, frozen recovery imports and signed-container helper
binding were verified. Both artifacts had valid approved signatures and
timestamps; the actual Setup archive matched the separate Core transport.

| Artifact | SHA-256 |
| --- | --- |
| Signed/timestamped MSI | `f2db9e4140ec8c95e012a2c8f1e1b6d70a3f63aa1872bc04092396f10b18c71b` |
| Signed/timestamped Setup | `22ce7d635185a65234c09e1b80b9f8885d6172f6c611ed5cbb8f6bb12ab981b2` |
| Internal Core ZIP | `3751d85e91c033d78d8b12291ba819133ca77bcd48e4bd916890c7dc7dd506d1` |

The real Setup attempt ran 05:49:28.968 to 05:51:03.999 UTC and exited 21
during online preparation. The old Agent remained running throughout; no
native switch occurred. Automatic recovery cancelled preparation, reached
`rolled-back` and removed its task by 05:52:31. Native Foundation 3.2.120,
Core 3.2.121 and all four private leaves remained unchanged.

The frozen diagnostic identified the new archive admission check: it expected
service-reader ACLs on a deliberately SYSTEM/Administrators-only installer
cache file. Fix `1970f5df61f551b305b24608241e1e21250f66a8` selects the
existing stricter private-cache validator. A representative native-ACL unit
test reproduced the failure before the fix. No access was broadened.

A separate full-size private fixture on the same guest then exposed differing
PowerShell/Python manifest ordering. Every metadata field and all 722 file
records were identical. Fix `5def4d45778972dd7a85a5c642ba7a58ad000564`
compares complete manifests in canonical filename order, retaining every
path/type/duplicate/contract/hash check. Its regression test failed before the
fix; 58 relevant Windows tests subsequently passed.

The corrected private fixture prepared all 722 files in 17.46 seconds,
published by rename in 3.49 seconds and moved them back with unchanged file IDs.
The real old Agent PID and fixture selector remained unchanged. This probe
executed no native installer scripts: it validates archive/NTFS preparation,
not installed MSI adoption, complete update timing or automatic native rollback.
The immutable 3.2.132 artifacts were retained without rebuilding. Installed
acceptance, the 120-second goal and the complete 42-case matrix remain open.

### 3.2.133 ordinary modern-with-OTA measurement and native pump RCA

The immutable candidate uses runtime source
`19e57ef107a4173f519dbed8c7d2216e34410103`, build checkout
`c59c6f80663116eaeb16b66bc27763f65a09aaa9` and successful CI run
`39738254239`. The complete Windows gate passed 2328 tests with three skips.
Actual signed MSI/Setup/Core archive binding and denied frozen helper/launcher
invocations were checked before installation.

Case `modern121-success-cold133-01` is an ordinary measurement; its filename
does not establish a controlled cold benchmark. Setup exited zero after
418.32 seconds. Online preparation kept the old Agent running. The candidate
reached `accepted`, created a fresh server WSS session at 07:26:04.122 UTC and
acknowledged the assigned policy at 07:26:04.241 UTC. All four private leaves
remained byte-identical. All 111 retained predecessor payload files, totalling
39,686,091 bytes, preserved their NTFS IDs, sizes and hashes through promotion.

Performance remains failed: the first observed old stopped state was
07:23:08.420 UTC, about 175.70 seconds before the fresh WSS session. The guest
did not expose SCM event 7036, so this is an observation-based bound, not an
exact SCM timestamp. Incoming Core adoption is unproven in this case: the
private observer rejected a legitimate signed filename containing a space.
The failed receipt is preserved and the observer was corrected for later runs.
Companion restoration initially failed its unchanged Foundation post-use
identity check. The recovery task later disappeared without manual invocation;
that alone is not full user-companion acceptance.

The captured phase metrics located the remaining polling path in the compound
native pump. Its ordinary helper phases already used pipe events, while native
callbacks still used `Start-Sleep 1`. A separate real two-channel transport
probe on the same guest measured 400 roundtrips twice: 11.759/12.038 seconds
with the original sleep and 0.093/0.097 seconds with event waits. The Agent PID
remained unchanged and no native product scripts ran. This demonstrates the
transport overhead, not an installed 120-second result. The event-wait change
retains every ownership, framing, authentication, grant and native-result check.
Its installed performance, automatic rollback and full matrix remain open.

### 3.2.134 controlled post-boot update: no duplicate Core copy, pause still failed

Candidate runtime source is `73b95a9477bf7134dafb55e6979c2fc3152373d3`;
build checkout is `13c6de7d3ed1a7b3da37d06c961f3d2a360a01b7`.
CI `39743640623` passed 4522 tests with 796 skips. The complete local Windows,
runtime, packaging and staged-harness selection passed 2330 tests with three
skips. Signed, timestamped artifacts were verified without changing historical
releases:

| Artifact | SHA-256 |
| --- | --- |
| MSI | `9baa58e0ea18d2b744108b3df3bdc80c1ea9e91f7ee208c6ea4b9bd9d2c2dcf4` |
| Setup | `fb762c38becfef1f39cd012c84cd4a597dabf11dcf277dc32253b5d66ce77f58` |
| Core ZIP | `dab0a5e3b9033adf2dec82db1753ba409ea7a94b123a7cdf698d27b0f5c94ba8` |

The actual signed Setup owner contains the event wait. Its embedded Core ZIP
matches the standalone archive, and its helper matches the MSI Binary stream.
Missing-capability helper/launcher invocations denied access. A recovery CLI
invocation with a missing operation exited 60 without creating a journal.

The supported frozen preflight verified Foundation 3.2.120 and selected Core
3.2.121. A new dedicated-guest boot was recorded before case
`modern121-success-cold134-01`; no cache-flushing or security exclusions were
used. Setup ran 08:14:43.469–08:20:59.124 UTC, exiting zero after 375.66 seconds.
Old-agent heartbeats continued during preparation. The candidate reached
`accepted`, with new WSS at 08:19:50.193 and matching APPLIED ACK at
08:19:50.306 UTC. All four private leaves were preserved.

Both complete identity comparisons passed: 111 retained predecessor files
(39,686,091 bytes) kept their NTFS IDs/hashes/sizes through promotion; all 722
incoming Core files (48,106,144 bytes), captured while the old Agent was running,
kept their IDs/hashes/sizes after native MSI adoption. Zero incoming files were
replaced. This directly confirms removal of the duplicate Core copy.

The pause requirement remains failed. The first coarse stopped observation was
08:16:57.592 UTC, at least 172.60 seconds before the new WSS. Exact SCM 7036
events were unavailable. The initial separate high-frequency observer failed
to load the ServiceController assembly, so it supplies no finer cold timing.
The event-wait transport microbenchmark therefore did not establish a material
installed improvement; no 120-second success is claimed.

### 3.2.134 real early crash: automatic native/Core rollback, cleanup incomplete

In `modern121-early-crash134-01`, the exact candidate executable was terminated
during trial. Setup ran 08:30:30.253–08:38:43.560 UTC and returned 67. Automatic
compensation restored registered Foundation 3.2.120 and Core 3.2.121, with fresh
old-version WSS at 08:38:43.919 and APPLIED ACK at 08:38:43.975 UTC. All four
private leaves remained equal. No manual native recovery was invoked.

The correctly rooted companion check found both original roles under
`Program Files/Endpoint Platform/Agent`, matching their original SID/session;
no Session 0 role was counted. The first private checker used the wrong fixed
directory; that failed diagnostic is retained alongside the corrected receipt.
One recovery task nevertheless remained Ready with result 60 after a
post-use Foundation identity-check failure. Thus automatic native/Core rollback
passed, while complete terminal cleanup did not. The pending state was saved
as `staged134-crash-cleanup-pending-22`.

The original MSI logging policy was restored. Eleven private native logs were
collected without rerunning Setup. The forward new-package log measured a
13.509-second SAFER signature verification, INSTALL 34 seconds, owner preflight
10 seconds and InstallExecute 20 seconds; InstallFiles took one second. These
figures do not support disabling signatures or any integrity check.

Separate source self timing on the restored 120/121 pair measured full
inspection 1.47 seconds, Foundation verification 1.02 seconds, native components
0.04 seconds and shared bytes 0.47 seconds. It attached to no other process and
recorded no values/arguments. An idle registry-barrier probe was also fast;
neither probe establishes the costs inside the actual authorized phases.

The next candidate adds default-disabled, protected opt-in function timings
inside those real phases, and one complete post-launch verification retry
without replaying launches. Diagnostic-enabled timings are excluded from
performance acceptance. The 120-second goal, remaining faults and complete
42-case matrix remain open; production/fleet publication remains out of scope.
