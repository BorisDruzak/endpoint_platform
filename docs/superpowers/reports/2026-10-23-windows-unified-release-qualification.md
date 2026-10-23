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
