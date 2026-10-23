# Staged Windows Foundation update acceptance

Status: **in progress; not accepted for production or fleet use**.

The source plan is `docs/superpowers/plans/2026-10-21-windows-staged-foundation-update.md`.
Only the dedicated disposable Windows guest is in scope. Historical artifacts,
snapshots and acceptance sequences remain unchanged.

## Latest controlled results: 3.2.142

Task 8 remains open: the 120-second pause goal and complete 42-case installed
matrix have not passed. Runtime source is
`0ab8e3ec76943c9e26a253474555cae3264799ac`; build and verification checkout is
`582868b33ca8957322fc4a99ab7915f052c3a0d3`.
[Exact-source CI 39840654394](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39840654394)
succeeded: 4605 passed, 830 skipped, 17 warnings in 347.31 seconds. The Windows
gate passed: 2439 tests, 3 skips in 335.57 seconds. Contract generation,
compilation and whitespace checks passed.

This candidate shares identical Foundation DLL/data while preserving each
entrypoint's independent PYZ closure. The compiled schema-2 inventory checks
all 122 Foundation rows, including valid empty metadata; executable bytes must
remain nonempty. All 183 project source hashes, 119 Core files, eleven frozen
entrypoint closures, timezone resources, required interpreter TLS resources,
MSI Binary, embedded Core and Setup recovery bindings passed. TLS verification
and the required interpreter policy resource remain intact. Candidates 3.2.140
and 3.2.141 were rejected before any guest installation; their artifacts remain
preserved.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| MSI | 103768064 | `5661e1423a5f7c10ded3dee1d79fe7e5d85e1750bac899d37f9b7aff7f2a3a37` |
| Setup | 145344248 | `02467b09d32062cbf179fd82f8450fc70d270ff81c90c4ce6c630d8d4a0d2e2b` |
| Core ZIP | 22751994 | `6c74135d44c8ead2d82951c0feba7751a8fc1ef5423ed2d59f4c76dfd2558dce` |

MSI and Setup have valid timestamped signatures. Both ordinary cases use
Foundation 3.2.120 with independent Core 3.2.121. Cold includes a real guest
restart and fresh baseline WSS/APPLIED policy before Setup. Conservative pauses
start at the last observed Running sample. Both rows exceed 120 seconds.

| Case | Setup seconds | First new WSS pause seconds | Latest WSS pause seconds |
| --- | ---: | ---: | ---: |
| Cold | 298.897795 | 135.335459 | 135.335459 |
| Warm | 318.567281 | 129.227401 | 164.549029 |

Both runs passed full Native/Core verification for the exact source and MSI,
fresh WSS/APPLIED policy, four private-leaf comparisons, unchanged Agent PID
during postflight, unchanged NTFS IDs/sizes/hashes for all 111 retained and 119
candidate files, and zero remaining recovery tasks. The warm run restored both
original user roles to the same SID/session; the cold run had none after boot.
These do not establish the required 2500+ legacy-file cases or full matrix.
Original latest-session verdict receipts are preserved; the warm first session
at 19:57:32.448493 UTC is reported separately from its reconnect at
19:58:07.770121 UTC. The server records only `disconnected` for the intervening
close, which does not establish its underlying cause.

Read-only signed probes measured complete command verification at
1.128/1.030/0.985 seconds under SYSTEM and 1.071/1.026/1.018 seconds using the
actual service token with its service SID. Agent PID remained unchanged and
probe tasks were removed. These probes neither launched Core nor attached a
debugger. They preimported modules and therefore do not measure cold module
loading or the actual transition's full startup delay. Cold Native finalization
took 13.69 seconds; service Running preceded Core process creation by 17.25
seconds. Those unexplained intervals remain under investigation.

Actual 3.2.142 early-crash rollback passed on the modern121 baseline. Setup
exited 67 after 388.486137 seconds; automatic compensation restored the exact
Foundation 3.2.120 and independent Core 3.2.121 source/package identities,
fresh old WSS/APPLIED policy, all four private leaves and both original user
roles. Postflight kept the live Agent PID unchanged and found zero recovery
tasks. All 111 retained NTFS identities/hashes/sizes matched. No manual recovery
or service start occurred. This is one rollback case, not full matrix acceptance.

Additional diagnostics do not change the performance verdict. A single fixed
`--print-version` invocation on the fully verified, unselected candidate while
the old agent remained Running took 19.429412 seconds, including 16.447827
seconds inside process creation. The subsequent Native upgrade passed its
functional checks but still measured a 130.640188-second conservative pause.
This experiment is performance-ineligible; it establishes the process-creation
boundary, not an antivirus, certificate or network root cause.

The source-only candidate selfcheck retains all candidate-file deny-write/delete
pins, full before/after hash/ACL/namespace verification, live owner checkpoints,
exact version output and a bounded deadline. Native authentication and the
60-second stability/180-second trial gates remain unchanged. The actual frozen
signed 3.2.142 Core passed this source function in an isolated fixture; this is
not a signed release of the new source. No 3.2.143 candidate has been reserved
or built. The updated source passed the complete Windows gate: 2455 tests,
3 skips in 336.71 seconds; contract generation, compilation and diff checks
also passed. These source results do not establish installed performance.

A separate read-only batch-pin-validation prototype measured
1.518057/1.480758/1.403336/1.509911 seconds in ABBA order, with identical full
Native inventory counts and 122 full byte reads in each pass. Its gain was
below 0.2 seconds, so that prototype was preserved privately and removed from
the implementation. The production agent PID and all trust settings remained
unchanged during that diagnostic.

Actual 3.2.142 no-proof timeout rollback also passed on the modern121 baseline.
The candidate was not accepted without the deliberately blocked proof; after
its unchanged 180-second trial deadline, automatic compensation restored
Foundation 3.2.120 and Core 3.2.121. Total Setup time was 502.807391 seconds,
exit 67. Independent full Native/Core postflight, fresh old WSS/APPLIED policy,
private-leaf preservation, all 111 retained NTFS identities/hashes/sizes,
the two original user roles and zero recovery tasks passed. Postflight kept
the live Agent PID unchanged. No manual recovery or service start occurred.
This adds one failure case; it does not close the complete installed matrix.

## Follow-up stability acceptance

The user accepted the measured pause on 2026-10-23 and requested completing
stability testing. Historical 120-second performance verdicts remain unchanged.
A fresh ordinary modern121-to-3.2.142 upgrade is followed by a separate
30-minute read-only soak, beginning only after full installed acceptance.
Required evidence: unchanged service/Core PID and creation times, one continuous
WSS session, advancing server heartbeat with age at most 90 seconds (the
configured three-heartbeat timeout), APPLIED matching policy, both original
user roles, no recovery tasks or active installer, and no new relevant Windows
runtime failure events. The observer samples every 30 seconds; any observation
gap over 60 seconds withholds acceptance. Full Native/Core and private-file
preservation are checked again after the soak. This bounded test does not
establish the complete 42-case matrix or fleet readiness.

Result: **PASS** for signed 3.2.142 on the modern121 baseline. The fresh
ordinary upgrade (`modern121-success-warm142-02`) completed in 300.062612
seconds with a 134.551703-second conservative pause; its original automated
120-second verdict remains false, with the observed pause accepted by the user.
Full Native/Core source/package verification, private preservation, unchanged
111 retained and 119 candidate NTFS identities/hashes/sizes, two original user
roles and zero remaining recovery tasks passed before the soak.

The independent soak lasted 1804.078972 seconds, with 61 samples and 61 distinct
advancing server heartbeat timestamps. The maximum observer gap was 30.000703
seconds; maximum heartbeat age was 17.833913 seconds. Service and Core PID plus
creation times remained unchanged, as did the WSS session. Matching policy
remained APPLIED, both original roles remained present, and no relevant runtime
failure event, active installer or recovery task appeared.

The final read-only postflight (`modern121-stability142-final-01`) again
verified exact Native/Core 3.2.142 source and MSI identities, all four private
leaves, both original user roles, zero recovery tasks and unchanged live PIDs.
The original WSS session was still open with fresh heartbeat and APPLIED
matching policy. No manual recovery or service restart occurred during the
upgrade or soak. Evidence: `stability-30m/final-acceptance.json`, all 61 raw
samples, artifact/observer admission binding and independent final postflight.
Observer SHA-256:
`3d5eb41bfad358fd2cda308058df16c16ac34471440cdce136537ac1ea568b4c`.
This result covers the existing signed runtime source `0ab8e3e`; it does not
include the separately committed, unpublished executable-selfcheck change.


## Historical controlled results: 3.2.139

Task 8 remains open: the 120-second pause goal and complete 42-case installed
matrix have not passed. Runtime source is
`be8056826327ee64a7d8fea2580823573d5e5a15`; build and verification checkout is
`550acd355f89aca13d3023d19b46544b64644805`.
[Exact-source CI 39811085445](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39811085445)
succeeded: 4561 passed, 828 skipped, 17 warnings in 274.24 seconds. The complete
Windows gate passed: 2396 tests, 3 skips in 313.91 seconds. Contract generation,
compilation and whitespace checks passed.

All 176 runtime source hashes and frozen project-module paths were verified.
The runtime has 118 files and tree digest
`b67c6a5a864f92398f82a99d36fa3e4ec8aa97f4c321f466c66caeaa9f09702c`.
The MSI and Setup had valid timestamped signatures. Embedded Core ZIP, MSI
helper and reviewed owner bindings passed; all ten actual Windows entrypoints
retained the exact 630-member timezone archive.

| Artifact | SHA-256 |
| --- | --- |
| MSI | `1cb4884de70d470cefb2a6dc0d612e08f4bba1aacc23da212f851830971b745c` |
| Setup | `6327dc1a673b7d0d623d6fda73d550df9396fb846916d2c126450ff632a1d61d` |
| Core ZIP | `a67143a75b204f704b52450e73190b111503898cbd1a5a1c324d2ee6283d3aff` |

Both versions below used genuine Foundation 3.2.120 with separate Core 3.2.121.
Cold means an actual guest reboot and fresh old-Core WSS/APPLIED policy before
Setup. The conservative pause uses the last 100-ms SCM sample still Running
and the exact new server connection timestamp. Every row fails 120 seconds.

| Candidate / case | Setup seconds | Conservative stop-to-WSS seconds |
| --- | ---: | ---: |
| 3.2.138 cold | 298.482125 | 123.208255 |
| 3.2.138 warm | 312.221925 | 138.578245 |
| 3.2.139 cold | 276.711356 | 121.827274 |
| 3.2.139 warm | 316.511989 | 143.714299 |

Both 3.2.139 runs passed full Native/Core verification for the exact source and
MSI above, fresh WSS/APPLIED policy, all four private-leaf comparisons, unchanged
Agent PID during postflight, all 111 retained and 118 candidate NTFS IDs/sizes/
hashes, and zero remaining recovery tasks. The warm case restored both original
roles to the same SID/session; the cold case had no original interactive roles
after reboot. Maximum SCM sample gaps were 0.190 and 0.191 seconds. Full ordinary
inventories showed zero replaced payload files. These are not the required
2500+ legacy-file runs.

3.2.138 separately passed actual automatic rollback after an exact candidate
process crash and after candidate-only outbound blocking prevented proof.
Both restored exact Foundation 3.2.120 and independent Core 3.2.121, fresh old
WSS/APPLIED policy, all four private leaves, both original roles and zero
recovery tasks. No manual recovery or service start occurred during either
fault. The no-proof daemon SCM collector ended before recovery terminal, so
that fine-grained pause measurement is missing and remains incomplete. The
3.2.139 controller waits for its bounded recovery observer. Installed rollback
of 3.2.139 itself has not yet been claimed.

The two new read optimizations preserve all Native/ACL/namespace/owner checks.
Parallel exact MSI reads retained all four full hashes and identical Native
counts in a read-only ABBA probe, saving approximately 1.15-1.66 seconds per
scope. Exact Foundation byte pins measured 4.778 / 3.669 / 3.707 / 4.693 seconds
in another read-only ABBA probe; complete results and Native counts matched,
with full byte reads reduced from 24 to 8. Installed finalization fell from
14.06/14.81 seconds in 3.2.138 to 10.86/11.45 in 3.2.139. Independent review
reported no findings and independently passed 140 related tests.

A signed read-only SYSTEM bootstrap probe on accepted 3.2.139 measured complete
command verification at 1.501 / 1.129 / 1.125 seconds with identical commands
and unchanged live Agent PID. It spawned no Core and made no Native product
changes. This steady-state result does not locate the variable startup delay
during an actual transition. A separate MSI logging diagnostic is in progress;
its timings are ineligible for ordinary performance acceptance. The complete
cause of the remaining delay is still open. Historical evidence is preserved.

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

### 3.2.135 authenticated phase timings and automatic rollback

Candidate 3.2.135 uses runtime source
`89245febd19e45447660253b0129ab6905544463`, build checkout
`1a94c0898fd6c8b80192f065ce0ed8b6300184cc`, successful CI
`39757456806` and the full Windows gate (2341 passed, three skipped).
Actual signed Setup/MSI helper and embedded Core bindings passed inspection.
Missing-capability helper/launcher and missing-operation recovery calls denied.

`modern121-diagnostic135-01` accepted with exit zero in 461.68 seconds.
The protected opt-in profiler was enabled, so this is excluded from performance
acceptance. A 100-ms observer measured Stopped at 10:02:14.015 UTC and new
server WSS at 10:05:50.459 UTC (216.44 seconds); maximum observer sample gap
was 0.207 seconds. APPLIED, four private leaves, all 722 candidate NTFS file
identities and 111 retained predecessor identities passed. Both original user
roles returned to the original SID/session and the recovery task was removed.

Authenticated body timings measured prepare 13.11 seconds (hashing 5.01),
reconcile 16.39 (hashing 4.70), finish 7.34 and compound-complete 6.47.
The first predecessor process admission separately took 16.65 seconds before
its phase body; the next admission took 0.017 seconds. These are measured
costs, not a claim that all hashing is redundant or that security can be skipped.

`modern121-early-crash135-01` ran without profiling. The exact new Core process
was killed during trial. Native compensation automatically restored Foundation
3.2.120 / Core 3.2.121; Setup returned 67 at 10:24:34.853 UTC. Fresh old-version
WSS/APPLIED and all private leaves passed. Initial terminal companion launch
failed closed in the warm launcher. The already registered recovery task then
admitted the dead owner, restored both original user roles, and removed itself.
The final 10:26:23 UTC check confirmed rolled-back, two matching original roles
and zero recovery tasks. No manual Native recovery or companion launch ran.
The earlier snapshot named `staged135-rollback-complete-22` was captured before
that cleanup finished; only `staged135-rollback-verified-22` represents the final
verified state. The failed intermediate observations remain preserved.

Source follow-up moves an authenticated predecessor inspection before service
quarantine and reuses only pinned immutable MSI digests/database semantics in
one phase. Native registration, ACL/namespace, every mutation boundary and full
Foundation/Core byte verification remain fresh. Installed timing for that
follow-up, the 120-second requirement and the full 42-case matrix remain open.

### Installed performance follow-ups: 3.2.136 and 3.2.137

Both candidates passed ordinary installed upgrade checks on Foundation 3.2.120 /
Core 3.2.121. Performance acceptance remains **incomplete**:

| Candidate/case | Setup seconds | Stopped to fresh WSS seconds | Conservative upper bound | Result |
| --- | ---: | ---: | ---: | --- |
| 3.2.136 cold | 369.0342 | 158.9054 | Not calculated | Accepted, exceeds 120 s |
| 3.2.136 warm | 388.6180 | 172.0707 | Not calculated | Accepted, exceeds 120 s |
| 3.2.137 cold | 354.6977 | 147.5657 | 148.3421 | Accepted, exceeds 120 s |
| 3.2.137 warm, case 02 | 382.7940 | 161.6202 | 162.2885 | Accepted, exceeds 120 s |

The 3.2.137 conservative bound starts at the last observed Running sample;
maximum service sampling gaps were 0.204/0.206 seconds. Every successful case
retained all 111 old payload file IDs and all 722 candidate file IDs, sizes and
hashes. Private leaves matched. Full Native/Foundation and complete Core
postflight passed without changing the running Agent PID. Fresh server-visible
version and matching APPLIED policy passed. Cold boot had zero original user
roles; the warm case restored both original tray/sensor roles with matching
user/session and no operation recovery task. This context difference must not
be hidden when comparing cold and warm results.

3.2.137 runtime source is `b8a56b3a2c18a3f90de978ea956257dc8722bd9e`;
actual fixed-entrypoint build checkout is
`1a3a51f33add8b3ca5d8feb12f16843a6a64e475`. Verification checkout
`78ea73f1f5834d1399e76469f0442ed27e513b50` differs only in a test fixture:
2372 Windows tests passed, 3 skipped (305.83 s); exact CI run
[39779147702](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39779147702)
passed 4540 tests, 823 skipped (273.20 s). Actual MSI/Setup signatures and
timestamps passed; embedded PowerShell matched the reviewed source, MSI Binary
matched the fixed helper and embedded Core ZIP matched the bound artifact.

Warm case 01 stopped before any candidate installation because the restored
historical Core 3.2.121 child exited 1. The underlying historical exit cause is
unknown. One explicit baseline service start then remained stable for 30 seconds;
case 02 began only after supported preflight and fresh old WSS/APPLIED passed.
This baseline fixture action is not evidence of automatic product recovery.
The failed case and both accepted guest snapshots remain preserved.

The fresh forward path now consolidates the existing five post-End(Commit)=0
functions into one authenticated helper. All five checks, ordered mutations,
durable boundaries, live grants and the final ready marker remain. Its cold
installed duration was 22.189 seconds; this alone did not achieve the target.
Recovery and repair retain the granular sequence. No new installed rollback
acceptance for 3.2.137 or full 42-case completion is claimed here.

An additional archived-MSI read-scope optimization is committed as source only.
The own-process read-only ABBA experiment on accepted 3.2.137 measured about
0.8 seconds saved per repeated full inspection. Pure MSI parsing/hashing fell
from three to one while fresh native product/property/feature/component counts
were identical (3/6/18/2214). Full inspection digests matched and the live Agent
PID did not change. It performed no product actions or attachment to another
process. These timings are diagnostic evidence, not installed acceptance of
the follow-up source.

| Follow-up commit | Change/files | Verification |
| --- | --- | --- |
| `f4b6b5f5d19efba1bfb27e283bf67a85f8e11604` | `perf(agent): consolidate verified native finalization`; compound installer, bridge, service launcher, MSI scope, owner PowerShell, three Windows test files, CODEMAP and spec | 169 related and 143 expanded passed; contract check, compile, diff check |
| `b8a56b3a2c18a3f90de978ea956257dc8722bd9e` | `build(agent): reserve native finalization candidate 3.2.137`; version, runtime identity, source/rollback tests and context golden fixture | 2 RED then 41 GREEN; unused production version read-only check |
| `46482fbd437223eb7a9ff3b2f18d919d8b739ba9` | `build(agent): pin native finalization runtime 3.2.137`; initial-runtime manifest | Independent frozen source/stage evidence, 14 metadata tests |
| `d742ed8a4b42f86425e53edf8d6b6d1c3d28a6e8` | `test(agent): bind setup conflict fixture to package capability`; setup-entry test | Targeted test passed after observed failure |
| `1a3a51f33add8b3ca5d8feb12f16843a6a64e475` | `test(agent): cover combined finalization orchestration`; wrapper test | 14 actual PowerShell orchestration tests passed, including failed finalization/publication |
| `78ea73f1f5834d1399e76469f0442ed27e513b50` | `test(agent): isolate platform API in conflict transport fixture`; setup-entry test | Portable no-win32api conflict test, complete Windows suite and exact CI passed |
| `59ab1c9d345e117dd118cb2a47990436a64ae319` | `perf(agent): retain pinned archived MSI inputs across metadata writes`; MSI scope, phase-read test, CODEMAP and spec | 2 RED then 134 related GREEN; own-process read-only ABBA, contracts/compile/diff check; not yet installed |
