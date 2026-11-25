# Windows188 PowerShell5.1 FoD correction

The user requested automatic Windows updates, including currently offline PCs.
The [187 receipt](2026-11-10-windows187-fleet-auto.md) preserves its valid
optional-origin correction and the separate missing-FoD failure on ADMIN-2.
Policy16 remains paused on187 after188 failed its Support migration gate; primary
Windows download remains177 and Linux183 is unchanged at this checkpoint.

## Reproduced cause and correction

System32 Windows PowerShell5.1 returns a nested Object[] from the former
`@($env:ENDPOINT_SUPPORT_FOD_NAMES | ConvertFrom-Json)`. With one missing
capability, the `[string]Name` parameter could not bind; with two, the existing
name guard rejected the nested array. The known failed187 receipt and original
servicing logs were preserved. No Add-Capability call occurred during that failed
attempt.188 uses direct `ConvertFrom-Json -InputObject` assignment and retains the
exact capability-name/operation-nonce guards and failure/reboot/conflict/unknown
classifications. Unknown servicing never becomes a new automatic attempt.

The regression executes the exact production script with actual System32
WindowsPS5.1 and the real `[string]` binder. Every native service/firewall/servicing
operation is replaced with isolated functions; an AST command/method allowlist
rejects unisolated additions before execution. It checks one/two names, exact
calls and completion flags. Invalid empty/foreign/nested inputs are rejected
before PowerShell. The initial uninjected-method guard failure was corrected
before the meaningful RED, without changing production code. The actual RED then
reproduced both failures; the narrow fix made them GREEN.

Context7 documentation was consulted, but its returned7.7 array examples are
newer than this target. Actual WindowsPS5.1 behavior and tests take precedence;
no newer `-NoEnumerate` API is used. Independent design/code reviews found no
blocker. Windows suite:2611passed,4skipped; focused FoD/OS/context tests57passed.
The provider is unchanged from the separately verified4227pass/441skip baseline;
that complete provider suite was not rerun for this Windows-only line change.

## Immutable media and publication

Runtime source `b7e1d2c1f8cfc1696a843b75ddbd3b1449411144`; native packaging
`156207043abc76c997a065c6c0d35e21f988224b`. The
[release record](../releases/windows-3.2.188-setup.json) binds actual signed EXE,
MSI and Support1.1.3 bytes. Signatures are Valid with timestamps from publisher4D;
MSI-bound image and frozen source were inspected. Runtime119files/tree
`843ff0d2e2fae5126e4fad86c9ef8fc37403138ab897efe025250caecac1442b`, component
`A67A0D1C-C797-48AF-9A84-853CE61D3E76`,321bound files. Exact signed observer108 is
unchanged. No Preview executable/archive is bundled.

Canonical candidate registration created installer
`d940b2df-4d94-4f79-bfa5-9647c3ec5f0e` and full-Setup
`6fc00a3f-5261-4303-bdc5-230a3863d8e8`, including the existing default AUTO
campaign transactionally. No campaign authority, quota, usage or expiry expansion.
Hash-checked public RAM staging was unmounted before canary assignment;
root550264832bytes exceeded two166973776byte response buffers plus110MiB reserve.

Capacity was recovered by archiving only an obsolete public171 upload duplicate.
The complete250767360byte archive was streamed off-host and each of six files'
SHA/size/owner/mode checked against inventory and original signed installer/MSI.
Archive SHA `6ecbf425eafc848e977b8e6992196c9a7884d1aabb1d628794821836e566b02c`.
The first cleanup guard correctly stopped before mutation because171 has a
full-Setup catalog row, not an enrollment-primary row. Read-only verification
established exact full-Setup UUID/source/digest; after correcting that guard,
no open process/work reference existed. Only those six duplicates and their
empty `/tmp/endpoint-setup171-b0d7cdb09cb3` directory were removed. The served171
artifact, registry, histories, failure evidence and operator originals remain.
Root717594624bytes after cleanup supported the actual188 publication peak.
No resize, boot-filesystem use, native journal, private identity, service or log
cleanup was performed for capacity.

## Actual missing-FoD canary

The authenticated Console created assignment
`45a3d1c8-95e7-46b3-a6a9-cb28367f95fa` on2026-11-09T23:36:16.211386Z for
ADMIN-2, UUID`c450fc70-63e6-4c2b-baf6-7de79820d63f`, source187/client108.
This is the local operator workstation; gateway source192.168.100.1 is not used
as an assumed workstation SSH address. Windows11 IoT LTSC26100.9711 had Client
FoD Installed, Server NotPresent, no System32sshd, no global sshd service, no
default OpenSSH port22 rule and no pending reboot. Old Support1.0.1 used the
bundled Preview. No manual FoD preparation preceded this canary.

The original known failed servicing receipt was archived unchanged. Read-only
baseline captured private-file/anchor hashes and original events. The existing
approved domain administrator/key and exact authenticated UUID-bound host pin
were preserved. A bounded manual diagnostic lease, rev3/gen1, expires
2026-11-10T00:31:44.401954Z; it is not an installation-grant renewal. Actual strict
SSH `whoami` succeeded before migration. The operator's first local read helper
inherited a PowerShell7 module path and could not resolve Get-FileHash; explicit
native module-path retry succeeded. Product preparation already pins that path.

At23:41:24 Windows DISM entered AddCapability for the exact Server name, PID7596,
DISM session2. At23:50:19.978713 the540second Python timeout killed its PowerShell
witness while Windows servicing continued. The protected v1 receipt for
operation `12f0efdddccd426f822bd3900495bbec` remains `servicing`; it was not
cleared or replayed. Old independent Support1.0.1 remains active.

The native188 assignment independently accepted0 at23:54:23.371618 with
191.404seconds and sensor1. This qualifies neither new Support activation nor
missing-FoD provisioning: optional Support failed with recovery_required.

Archived CBS log uniquely correlates session `31289507_3567631198` initialized
at local04:41:24 to the exact OpenSSH Server package. Its capability finalized
Installed/S_OK at04:55:58; session finalized S_OK/no reboot/no repair at04:56:01.
The actual signed188 `--inspect-os` subsequently verified the complete Microsoft
System32 closure9.5.6.4. These facts establish Windows servicing completion,
not completion of the killed helper's firewall cleanup or original boundary proof.

The23:50 snapshot still had the disabled Endpoint nonce reservation. After CBS
commit Windows had replaced it with its standard OpenSSH Server allow rule,
enabled for Domain. Global sshd remains Stopped/Manual/PID0; no global OS SSH
listener was started. The original rule snapshot existed only in the killed
process's memory. No rule was removed/disabled under an inferred ownership claim.
Windows Firewall event channels were already disabled, so they provide no
historical authorship receipt. The original188 unknown receipt and all evidence
remain preserved for a separately audited recovery decision.

Policy16 remains PAUSED/target187/all_active/max2. No188 source qualification or
primary promotion was created. A new189 runtime is being developed to preserve
operation-bound baseline/completion outside its caller and avoid killing long
servicing operations. Legacy v1 unknown outcomes remain held. An actual fresh
missing-FoD test is still required; source177 device2 has a running foreign
ProgramFiles/OpenSSH sshd, so it must not be silently repurposed as a pristine
test. Future/offline admission is conditional on the resumed target's exact source
qualification, freshness/readiness and qualification expiry.

Operator evidence: `C:/endpoint-platform-wix-build/windows184-inbox-20261109`,
`artifact188-qualified.json`, `fleet188-*.json`, `tests188-windows.txt`,
`baseline-admin-before188-native-env.stdout`, `admin2-fod-firewall-before188.json`,
`admin2-os-servicing187-failed.json`, `admin2-before188-actual-ssh.stdout`, and
`staging171-archive-verified.json`/the retained complete archive.
