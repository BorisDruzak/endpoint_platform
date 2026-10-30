# Domain launch policy audit for Setup 3.2.156+setup.1

On 2026-10-31 (Asia/Yekaterinburg), the live `sosnadmin.local` domain and the
current `network_configuration` remote were inspected. Two narrowly scoped
installer exceptions and a certificate-only workstation GPO were applied.
Replication and a domain workstation pilot passed. Fresh installation on
`B2-ZHKH-S5` remains unverified because its remote management ports do not answer.

This is a follow-up to [the Setup progress delivery](2026-10-31-windows-setup-progress.md).
The earlier B2 attempt reached enrollment and waited for `MANUAL_POLICY`; it is
not evidence of an SRP denial. The campaign correction and the new progress
window are independent of the domain launch/trust changes recorded here.

## Live findings and changes

### Exact SRP exceptions

The GPO `Ограничение запуска программ`
(`CAF5EFFD-894C-4166-81D5-9B586E7B243A`) has 33 enabled links. Its User policy
defaults to Disallowed and ignores certificate rules. Its Machine default is
Unrestricted. Effective behavior therefore depends on the user/computer policy
combination; administrator success alone does not qualify a standard user.

The existing `C:\Program Files\Endpoint Platform` allow rule permits an installed
path but does not specifically admit a downloaded Setup EXE. Added two User hash
rules, using the existing native MD5 plus SHA256 rule format:

| File | SHA256 | Rule GUID |
| --- | --- | --- |
| `EndpointAgentSetup-3.2.156+setup.1-x64.exe` | `c98851e539004384d5b216d075b7b16a33888990840c8f218514dcb843590cbf` | `c01fd44f-9816-4ae3-9d52-2ddc4e6d6a01` |
| `EndpointAgent-3.2.156-x64.msi` | `ab6cde32554798a18b446c8e33ce6f0926eba6a85439bc7224a08a88b25a1073` | `d480504d-83d9-4645-908e-cf3dbcc019b7` |

Both signatures were rechecked as Valid, signed by
`4D4C23389F5FF77BC4EB32044761019EAE8FB776`. User version changed from 160 to 178;
Computer version remained 26. All 183 pre-existing filtered policy values,
including default levels and paths, were preserved. Native GroupPolicy cmdlets
also added their registry editor identifier to the existing registry CSE entry.
Other existing GPO versions/settings/permissions and original links were retained.

### Workstation certificate trust

Previously, the Endpoint CA and publisher certificates were carried by three
GPOs restricted to 5, 3 and 98 explicit computer SIDs. B2's current computer SID
was in none of their Apply sets. Adding it to the OpenSSH GPO would also change
SSH/firewall behavior, so certificate delivery was separated.

Created and linked `Windows - Endpoint Platform - Installer Trust 20261031`
(`DFC1DBA8-3270-4F5E-9C17-7CB7E31EA54F`):

- Machine policy only; Authenticated Users have Read, Domain Computers have Apply.
- Existing verified WMI query `Win32_OperatingSystem WHERE ProductType = 1`
  limits application to Windows workstations, excluding domain controllers and
  member servers. Reusing this filter does not apply the OpenSSH GPO itself.
- Exactly two certificate values: LocalMachine Root
  `EFBED1F8572927112500D8A6E3437CEBB63F9E64` and TrustedPublisher
  `4D4C23389F5FF77BC4EB32044761019EAE8FB776`.
- Public certificate data only. An older publisher blob contained a key-provider
  reference; the new GPO uses a clean public-only serialized certificate
  (1761 bytes), retaining the identical certificate and removing that reference.
  No private key was exported. The existing VM's old reference could not acquire
  a private key; older GPOs were not rewritten.
- No tasks, installation payloads, firewall settings, UAC changes or antivirus
  exclusions. Final Computer version is 3, User version is 0.

The filtered policy inventory contained no configured `DisableMSI`,
`AlwaysInstallElevated` or Defender exclusion settings that explain the install
symptom. The EXE requires administrator elevation to install a machine service.
An SRP allow rule permits launch; it does not grant administrator rights.
Unattended installation requires an explicitly targeted administrative/SYSTEM
delivery, rather than an elevation-policy bypass.

## Verification

- `Test-UserSrp.ps1`, using a native `/MT` C probe on domain VM123:
  two temporary non-administrator profiles with User SRP default Disallowed.
  Without the hash rule, exact EXE and changed-byte control both returned level 0.
  With the rule, exact EXE returned Unrestricted (262144), while the renamed
  changed-byte copy remained Disallowed (0). The installer itself was not run by
  these profiles. This validates the rule format and positive/negative match;
  it is not a claim about B2's currently cached user policy.
- `verify_diff.py`: semantic comparison of the 22 original GPOs against the
  23-GPO result passed. Only 18 SRP values for the two new rules and two values
  in the new certificate GPO were added; original domain links were preserved.
- `Verify-ReplicaLocal.ps1`: AD versions plus SHA256 of `GPT.INI` and applicable
  Machine/User `Registry.pol` are identical on AD-MAIN and DirectumServer.
  SRP combined version is 11665434; trust GPO version is 3.
- `Verify-WorkstationPolicy.ps1`: computer `gpupdate` returned 0 on
  `DESKTOP-2EVR855`/VM123. RSoP lists the new trust GPO enabled, allowed by the
  filter, without AccessDenied. Both certificate policy entries are present.
  Exact signed Setup preflight returned 0 and verified the existing native
  Foundation 3.2.158. Credential/identity/origin/CA hashes, ACLs and timestamps,
  and the running service PID were preserved. This is an existing-device check,
  not fresh installation or downgrade acceptance.
- All temporary SRP accounts and profiles and their scratch directories were
  removed. No production agent identity or protected installation state was reset.
- B2 was rebound through AD GUID `b7d85066-c0ec-4d59-90f2-f1093ff00d2e` and
  computer SID ending `-7192`, then resolved by its current DNS name to
  `192.168.101.48`. Ports 22, 445, 3389, 5985 and 5986 did not answer on the final
  check. This does not prove that the computer is powered off.

## Network configuration findings outside this change

The inspected remote is `BorisDruzak/network_configuration` at
`b1f24e80c7cca59a82e0b96bede517300694213e` (2026-10-18). Its local checkout
`C:\Users\admin-2\Documents\network_configuration` is 533 commits behind
`origin/main` and has a pre-existing untracked `baseline/`; neither was modified.
GitNexus does not index that repository, so current remote documents were checked
directly and important findings were compared with live AD/SYSVOL.

| Live finding | Consequence / limit |
| --- | --- |
| Default Domain Policy startup/logon references `SCRIPTS\netfix\enable_dhcp.ps1`; the actual `netfix` directory is empty | The referenced DHCP repair cannot execute. Its startup entry also supplies `powershell.exe` as a PowerShell-script name. This is not established as the enrollment-wait cause. |
| `NET - Force Auto DNS` passes the `netfix` directory to `powershell.exe -File` | A directory is not an executable script. The intended DHCP/DNS behavior needs review before changing workstation networking. |
| Both WSUS GPOs have Computer settings disabled | Their stored WSUS settings are inactive through those GPOs. Actual client update sources still require RSoP/client verification. |
| User SRP permits writable areas including `C:\ProgramData\*` and several profile paths | Existing application-control weakness; exact Endpoint exceptions do not resolve the broader allow-list design. |
| Default Domain Policy has `LockoutBadCount=0` and `LmCompatibilityLevel=1` | Account lockout is disabled and legacy LM/NTLM compatibility remains a separate security debt. |

Related committed evidence already describes
[SRP and missing client RSoP](https://github.com/BorisDruzak/network_configuration/blob/b1f24e80c7cca59a82e0b96bede517300694213e/docs/compliance/fstec-117/ad/2026-10-16-software-installation-and-srp-findings.md),
[broken script references](https://github.com/BorisDruzak/network_configuration/blob/b1f24e80c7cca59a82e0b96bede517300694213e/docs/compliance/fstec-117/ad/2026-10-14/gpo-policy-settings-deep-dive.md), and
[disabled WSUS GPOs](https://github.com/BorisDruzak/network_configuration/blob/b1f24e80c7cca59a82e0b96bede517300694213e/docs/compliance/fstec-117/ad/2026-10-15-wsus-gpo-review.md).
These broader network/security settings were not changed during installer repair.

## Remaining acceptance and recovery

B2 must receive computer policy and its user must refresh policy/sign in again
before a real new-enrollment retry can establish acceptance. Use the published
`3.2.156+setup.1` EXE with administrator elevation. The existing expired request
cannot be resumed. Verify native installed service, successful server enrollment,
correct campaign and final Setup result on that actual machine.

Native SRP backup ID: `1f10e7a0-0a9b-4298-93a1-f4bc7de3d53d`, on AD-MAIN at
`C:\Program Files\EndpointPolicyAudit20261031\srp-backup-20261030T233630Z`.
For selective rollback, remove only the two recorded hash rules and disable/unlink
only the new certificate GPO. Avoid restoring the whole GPO over later changes.
The earlier trust/SSH/pilot GPOs remain independent.

Detailed snapshots, native test source, mutation receipts, replica hashes and
cleanup evidence are retained outside Git at
`C:\endpoint-platform-wix-build\ad-installer-audit-20261031`.
No server restart, runtime artifact replacement or fleet installation was done.
