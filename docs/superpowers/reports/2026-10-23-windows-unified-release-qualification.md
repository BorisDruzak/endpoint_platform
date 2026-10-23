# Unified Windows release qualification

This release combines the staged Foundation updater with TCP/WSS recovery from
`61784dc6d35570404952f8c512641785e41b6904`. Source publication, catalog promotion,
installation and installed acceptance are separate gates.

## Qualified release 3.2.149

Runtime source `1ae42be4180751e271f2e37c7e12870d199c78bf`, immutable build
checkout `5923e46708e8145e76e644187d35e9c082e3419c`. The integrated TCP
implementation and regression test are byte-identical to `61784dc6`; the
integration commit is `5939a55`, rather than an ancestor merge of that commit.

Exact-source [CI 39956079592](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39956079592)
passed. The full Windows/packaging gate passed 2,370 tests with 5 skips;
canary tests passed 422; tools passed 398 with 158 skips. Contracts, compilation,
diff checks, 11 embedded source closures and 122 source bindings passed.
The first full source run retained one unchanged synthetic MSI timeout failure;
its isolated retry passed within the original 30-second bound and the subsequent
complete source run passed. No timeout or acceptance check was weakened.

| Artifact | SHA-256 |
| --- | --- |
| Setup EXE | `7bb9f4ba71dac2df0dcb504c263fd83571b505431321e670e661458c8fb3f171` |
| Native MSI | `1b4577fbf330f1414dd7b03914deaefdb3f87b94780533849579ab3df8739632` |
| Core ZIP | `1fe55e997fd3dca486c4c75a38ce735f27db66e5dacbf5c9d7f38a23a632cbb1` |

Setup and MSI have valid organizational Authenticode signatures and timestamps.
The Core requires launcher 3.2.149; no Core-only rollout onto an older Foundation
was created.

### Actual dedicated Windows acceptance

All seven required installed cases passed against these exact immutable bytes:

| Case | Setup total seconds | Conservative service-stop to fresh WSS seconds | Outcome |
| --- | ---: | ---: | --- |
| Native 120 / Core 121, first success | 319.700 | 145.384 | Native/Core 149 accepted |
| Native 120 / Core 121, repeated success | 311.160 | 141.172 | Native/Core 149 accepted |
| Genuine Native/Core 79 | 660.855 | 259.640 | Native/Core 149 accepted |
| Genuine 63 through canonical original 79 | 647.369 for final leg | 256.893 | Native/Core 149 accepted |
| Candidate early crash | 357.323 | 263.311 | Automatic rollback to original 120/121 |
| Candidate withheld health proof | 527.092 | 428.699 | Automatic rollback to original 120/121 |
| Original installer owner loss | 181.638 until killed owner exit | 400.228 through recovery | Automatic rollback to original 120/121 |

Every case preserved all four private-file states, restored the captured
interactive companion roles where present, and ended with no recovery tasks and
matching APPLIED policy. Candidate adoption retained all 118 file identities and
hashes. Legacy preparation verified the 2,543 historical files while the old
agent remained running; the candidate was not copied a second time.

The strict 120-second pause gate remains **failed**; legacy total time also
exceeds the original 600-second bound. The user accepted this measured limitation
before completing stability qualification. These results do not establish a
two-minute pause across the fleet.

An exact four-tuple TCP reset recovered in **39.161 seconds**, with the same
service and Core process instances, a new WSS session and matching APPLIED policy.
The final repeated-success installation then passed **1,804.040 seconds** of
continuous observation: 61 distinct heartbeats, maximum heartbeat age 6.097
seconds, maximum observation gap 30.001 seconds, unchanged service/Core/WSS,
original two companion roles, no runtime failure events or recovery tasks.
Complete postflight afterward verified the exact Native/Core source and package,
private data and unchanged process instances.

One subsequent reboot of the dedicated test VM proved the actual installed
schema-2 volatile marker disappeared while its protected persistent operation
witness, ACL and native-attempt binding remained intact. Exact Native/Core 149,
private state, fresh postboot WSS and matching APPLIED policy passed again.
This boot proof covers service recovery; the original preboot interactive session
does not survive a reboot and is not claimed as a restored interactive session.
No production workstation reboot was performed.

The first external acceptance queue stopped before any mutation of the next
guest case because its snapshot helper omitted an exact historical snapshot.
That failed orchestration log was retained; the helper allowlist and an overlong
output snapshot name were corrected without changing product bytes. Only the
remaining cases were resumed, and the final admission receipt binds all seven
actual proof hashes. No rejected candidate evidence was reused as 149 acceptance.

### Main and production publication

After installed acceptance, stability and boot proof passed, verified build
`5923e46708e8145e76e644187d35e9c082e3419c` was fast-forward published to `main`.
The existing production backend and contract trees are unchanged, so this
client-only release requires no new server migration or service restart.
Production capacity was checked before private artifact staging.

Canonical services registered the immutable Core and updated only the release
allowlist of the two applicable active Windows enrollment campaigns, preserving
other policy and quota fields. Their transaction committed before canonical
Setup registration made 149 the newest active default. Audits and a fresh
read-only catalog check confirmed default 149, compatible Core registration and
both campaign allowlists. Expired/revoked campaigns were not revived and no
device success was fabricated.

The authenticated browser displayed default 149 with the exact build revision
and Setup/MSI hashes. Its actual downloaded Setup matched SHA-256 and had a valid
signature and timestamp; no browser console errors were captured for this flow.
The signed Setup remains the supported Foundation upgrade path.

### Final live delivery

All four connected production Windows workstations now have independently
verified Native and Core 3.2.149, exact source/package bindings and preserved
private-file states. Each established a fresh WSS session and sent a matching
APPLIED acknowledgement after that connection. The four production devices plus
the dedicated test VM accounted for every fresh live device at final
reconciliation; all five reported Core/launcher 149.
Final SYSTEM observations on all four real workstations also confirmed an
accepted journal, one Core child of the running service, no active installers
and no remaining staged-recovery tasks.

| Real workstation predecessor | Full Setup seconds |
| --- | ---: |
| Native 120 / Core 143 | 145.823 |
| Native 120 / Core 121, workstation A | 157.240 |
| Native 120 / Core 121, workstation B | 151.845 |
| Native/Core 79, after the exact ACL preparation below | 551.682 |

These are complete Setup durations on real workstations, not measurements of
their service-stop intervals. They do not replace the stricter VM pause results
above. No production workstation was rebooted.

Four registered production Windows workstations remained offline: three are
covered by the existing deployment GPO and one by the separate canonical legacy
assignment. Their actual installations and subsequent policy acceptance remain
unverified until they reconnect. The final inventory reconciliation added the
fourth offline machine after confirming its existing Allow/Apply Group Policy
membership; no policy scope was expanded for that correction. Other historical
test registrations and ALT devices were not represented as upgraded Windows
workstations.

The production browser displayed all four connected workstations with both
versions 149. Activity Analytics opened successfully and showed fresh IDLE
observations for an updated workstation, retaining its update gap as UNKNOWN.
The dedicated headless VM remained ONLINE/UNKNOWN after its reboot, without an
interactive login; transport status was not converted into employee activity.

The combined operator verdict binds the seven Native cases, three automatic
rollback cases, TCP recovery, full stability/boot evidence, main/catalog checks,
actual downloaded artifact, four installed receipts and four deferred
assignments. Detailed deployment identities and private evidence stay outside
the repository. The original strict 120-second VM performance gate is explicitly
false in that verdict.

### Domain delivery and legacy data-policy preparation

The existing domain deployment task now points to the signed 149 client script
and full Setup, preserving its exact five-computer scope, task identity,
schedule, SYSTEM principal, no-termination setting, share permissions and
historical payload. Its computer GPO version advanced from 6 to 7; user-version
bits and the existing extension registry were preserved. A separate deferred
assignment was published for the one offline Native63 predecessor, with a
machine-only payload share and the canonical 63-to-original79-to149 path.
Existing domain links and other policy scopes were checked unchanged.
Assignment is not an installed-success receipt.

Operator Authenticode checks bind the exact signed, timestamped payload bytes.
Authenticated DC copies are hash-bound before publication and the administrative
publisher is pinned while read and executed. The DC does not trust the signing
CA in its machine store; no global trust-store change was made or claimed.
Client SYSTEM signature, timestamp, publisher and hash gates remain enforced.

One real Native79 predecessor safely refused online staging before a data
capture, staged journal, SCM stop or native invocation: two private leaves had
the historical inherited service-modify/updater-write-delete DACL, while the
current credential/CA policy requires service-read/updater-write. The original
service remained running. Its terminal pre-journal recovery task and failed
receipt were backed up rather than reused as success.

The operator narrowed only those two exact historical DACLs under the canonical
global transaction lock. Both files were pinned against writing/replacement and
bound before either mutation to full 128-bit NTFS identity, volume, owner/group,
descriptor, regular-file/single-link metadata and a DPAPI-protected content
baseline. All private contents and identities remained unchanged; the complete
root/leaf snapshot then passed the unchanged product validator. Independent
review required and verified the pre-write handle binding. A fresh attempt used
the original signed 149 bytes and passed full Native/Core, private-state and
fresh WSS/APPLIED acceptance. The DPAPI-protected pre-repair content baseline
still matched afterward. No package/check relaxation was introduced.

## Candidate 3.2.146: rejected before publication

Runtime source `1045a0d81ae5fccbb254308501968c8e7a8949ac`, build checkout
`055f9a2250a58ca399229ff1eebbbd2e8d834a23`.
Exact-source CI run `39928132089` succeeded. The Windows/packaging source gate
passed 2,611 tests with 13 skips. Signed timestamped MSI/Setup, 11 embedded
source closures, native inventories, TLS resources and timezone payloads passed
their artifact checks. These checks did not establish installed acceptance.

The following dedicated Windows runs passed:

| Run | Total seconds | Conservative service-stop to fresh WSS seconds |
| --- | ---: | ---: |
| Foundation 120 / Core 121 to 146 | 312.715 | 128.047 |
| Genuine Foundation/Core 79 to 146 | 668.102 | 254.645 |
| Genuine Native 63, canonical 79 intermediate, then 146 | 653.207 for the final upgrade | 252.546 |

Original 120-second performance gates remain failures. The legacy migration also
exceeds the original 600-second total-time gate. A two-minute pause is not a
verified fleet-wide result. Successful upgrades preserved all four private leaves
and reused all 118 candidate file identities through native adoption.

Candidate crash and withheld-WSS-proof injections automatically rolled back to
the original Foundation/Core pair, preserving private data and restoring captured
user roles. An exact TCP connection reset recovered in 40.598 seconds with the
same service/Core processes, a fresh WSS session and matching APPLIED policy.

The owner-loss injection during the authenticated native `foundation-config`
callback failed automatic recovery. The watchdog waited for the original owner,
then returned 60. The old native product registration returned, but the original
agent service did not return to Running. The failed guest state was preserved in
a separate snapshot. A subsequent explicitly manual diagnostic recovery also
failed; it is not automatic-rollback evidence. No publication admission receipt
was issued and no production workstation installation used this candidate.

## Owner-loss cause and correction

The Windows Installer rollback cleared only `SE_DACL_AUTO_INHERITED` on the
existing enrollment data directory (control `0x9404` became `0x9004`). The native
directory identity, owner, group, four ACEs and private leaf identities/descriptors
remained unchanged. Private byte comparison also passed. The strict original
snapshot check correctly rejected the descriptor difference during recovery
`prepare` (`compound_installer._prepare_recovery` to
`installer_data_security.before_native`).

The correction restores the exact original root descriptor bit only after a
fresh owner proves real empty MSI Begin/End settlement. The compiled owner policy
denies recovery preparation without that proof. The helper requires a live
mutation grant, unchanged full native identity and every other snapshot byte.
It pins the directory against deletion/rename with directory-list access, then
uses low-level SetFileSecurity to avoid propagating changes to children. The
original capture remains immutable and the full snapshot must match afterward.
Changed ACL bodies, owners, identities, leaves, protection flags, pre-native
captures and ordinary installation requests remain rejected.

Regressions first failed (11 data tests, then the separate missing-settlement
policy test); 77 affected tests now pass. The native NTFS regression checks exact
descriptor restoration, unchanged child ACL bytes, a lost-owner rejection and a
blocked rename during the write. A new immutable candidate and fresh dedicated
Windows acceptance are still required before publication.

API references used during the correction: [security descriptor control](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control),
[automatic ACE propagation](https://learn.microsoft.com/en-us/windows/win32/secauthz/automatic-propagation-of-inheritable-aces),
[SetFileSecurity](https://mhammond.github.io/pywin32/win32security__SetFileSecurity_meth.html),
[full native file identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info).

## Candidate 147 owner-loss rejection and boot classification

Candidate 147 passed exact CI 39945610705 and signed artifact/source checks.
Its actual owner-loss case recovered through the corrected ACL preparation and
returned healthy Native/Core 147, original companions, private data and APPLIED
policy. It nevertheless failed acceptance: live owner loss required rollback,
while recovery classified the host as rebooted and accepted the new version.
No publication receipt was issued; no production workstation received 147.
The unexpected state is preserved in snapshot `staged147-ownerloss-accept-23`.

Captured WMI LastBootUpTime was `20261020125508.151071+300`, then became
`20261021161917.633209+300` without any actual reboot event. On the dedicated VM,
a controlled +120-second clock correction followed by a WMI service refresh
shifted that timestamp by 119.987 seconds while the kernel boot GUID stayed
identical. Restoring the clock/provider changed it again by milliseconds.
Clock adjustment alone reused the cached provider value. Thus provider cache
refresh, rather than a reboot, can change the previous admission input.

## Candidate 148: rejected before native build

The kernel-GUID replacement passed its focused tests, the full Windows/packaging
scope (2352 passed, 5 skipped), canary (422 passed), tools (398 passed, 158 skipped)
and exact CI 39951041720. Its Core/source manifest was frozen from 3f158cfa.
An actual dedicated guest restart then showed the kernel boot GUID unchanged,
while kernel startup record 1923 replaced record 1650. This invalidated the
GUID-only assumption. The native build waiter was stopped before signing;
no Native 148 installation, admission, catalog promotion or production rollout
occurred. Evidence and the frozen Core remain preserved.

A subsequent event-log prototype was also rejected before freezing: a delayed
startup event could arrive after capture without another reboot. Retaining an
older event anchor therefore did not prove a reboot after capture. Its source
and failure evidence are retained separately; it was never a published release.

## Volatile boot witness and conservative native attempt gate

The replacement uses documented volatile HKLM keys under the private 64-bit
EndpointPlatformStagedBoot namespace. The signed original owner exclusively
creates a persistent operation witness, checks its SYSTEM/Administrators-only
protected ACL, flushes it with RegFlushKey, and captures a fresh volatile child.
Recovery only opens existing witnesses, with no-follow registry semantics. It
never recreates them. Missing parents, changed ACLs, links, access failures and
deleted handles remain errors. Only an exactly missing volatile leaf under an
intact private witness proves full shutdown. Product cleanup never deletes
witnesses or markers. SYSTEM and administrators remain trusted authorities.
Fast Startup/hibernate preserving the marker cannot release a reboot gate.

Before every forward native invocation, an authenticated owner durably publishes
an unresolved attempt with a fresh marker. A publication failure prevents launch.
Unknown attempts block trial and request compensation. Zero requires real empty
MSI settlement and verification of the exact candidate Native release before
atomic outcome publication. 3010/1641 retain the marker bound before launch.
Thus an old satisfied reboot record cannot authorize a second interrupted
attempt. Historical timestamp, kernel GUID and event identities remain
conservative compensation/reboot-block inputs.

On the actual dedicated VM, a marker survived creator-process exit and a
+120-second clock adjustment plus WMI refresh. A real guest restart removed the
volatile leaf while preserving the private persistent witness. This standalone
lifecycle proof is not an installed candidate acceptance result.

The affected source scope passed 113 tests, including actual private HKLM keys,
dangling REG_LINK, ACL drift, access/deleted-handle failures, pending-publication
faults, exact candidate binding and compiled owner settlement/control-flow checks.
Independent review passed 84 focused tests and found no Important/Critical
findings. A new immutable candidate still requires signed artifact checks and
fresh installed owner-loss, rollback, TCP and stability acceptance.

References: [volatile key semantics](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw),
[registry durability](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regflushkey),
[registry open semantics](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw).

## Historical preparation before 149 qualification

Administrative SMB access to the three previously blocked workstations was
established through an isolated policy scoped to their exact computer identities
and the verified operator source. No firewall was disabled, no workstation was
rebooted, and supplied password text was not needed or persisted. Five working
machines passed signed Setup preflight; the sixth requires the qualified
canonical 63-to-79 intermediate before the new Setup. The dedicated Windows VM
is separate from those six machines.

Applicable active enrollment campaigns and the existing domain deployment task
were inspected and backed up. Their scope and public defaults have not been
promoted while installed acceptance is incomplete. Historical immutable media
and rollback inputs remain preserved. An existing minor documentation issue in
the standalone MSI example (missing mandatory signed SetupImagePath) is deferred;
delivery uses the supported full Setup EXE without relaxing that binding.
