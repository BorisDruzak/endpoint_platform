# Unified Windows release qualification

This release combines the staged Foundation updater with TCP/WSS recovery from
`61784dc6d35570404952f8c512641785e41b6904`. Source publication, catalog promotion,
installation and installed acceptance are separate gates.

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

## Production readiness

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
