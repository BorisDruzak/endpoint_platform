# Windows Setup 192 Support activation

## Investigation on test120

The original 3.2.191 assignment `4dd93c38-249f-4f21-a740-28755dd35c62`
applied successfully at the native installer level. The Support replacement
requested initialized readiness at 13:20:19Z. The service configuration and
signed 1.1.4 image were restored around 13:20:25Z, and Setup wrote
`support_install_failed` at 13:20:26Z. The generic failure receipt and Windows
service events do not identify the original exception.

The original Support and native receipts were archived on test120 before a
controlled repeat. Setup preflight confirmed 3.2.191 was already current and
that there was no active native installer transaction. After restoring the
exact signed 1.1.4 Support image on this test VM, the same signed Setup 191 ran
quietly as SYSTEM and automatically installed Support 1.1.5 at 14:04:04Z.
It returned 10 (already installed) and did not repeat MSI. The controlled
repeat did not reproduce the original failure. The temporary test task was
removed.

## Change in 3.2.192

The signed 1.1.6 helper distinguishes image replacement, service start, and
readiness failures eligible for a retry. It does so only for known transient
Windows errors or an explicit readiness failure, after confirming the prior
image, configuration, authority and running service were restored. Setup
retries the signed Support helper once and records the original stage in
`activation_retry`. Unknown rollback, changed authority, and repeated
failures remain failures. The native MSI path is outside the retry.

251 targeted Windows tests passed, including simulated transient failures,
unverified rollback and preservation of service authority. Six focused
cases also passed after the version bump. Validation compared the frozen
Setup entry point, provisioning module, and Support code with reviewed source.
The EXE, MSI and Support image had valid timestamped signatures. The package
uses the Windows-serviced OpenSSH runtime.

## Native update on test120

Production registered the signed 3.2.192 candidate and assigned it only to
DESKTOP-9ST5HO2 (.120), running Windows 11 build 26100 with Windows OpenSSH
already installed. Assignment `d1c452b8-ad1b-4431-9452-ed8bfb97ccc3` updated
Core and Foundation directly from 3.2.191 using observer 1.0.8.
Support 1.1.6 activated automatically at 14:24:34Z. The local Setup receipt
reported installed with no error or `activation_retry`. Both the staged and
active Support binaries matched the signed artifact. The Support service
was running in automatic mode and reported 1.1.6 to Endpoint. The existing
global OpenSSH service kept its process and start mode.

The assignment reached APPLIED at 14:27:54Z, native exit 0, with all four
private materials preserved, six stable samples over 185.779 seconds, and
one genuine UserSensor. Observer 1.0.8 reported ready Core/Foundation 3.2.192.
Inventory was observed again at 14:28:30Z and had no warnings. Fresh
UserSensor and activity arrived after APPLIED. The retry path was exercised
by automated tests.

## Independent SSH on test120

At 14:36:02Z, a key-authenticated administrative command through the
UUID-pinned reserve tunnel succeeded on the exact signed Support 1.1.6 image.
EndpointAgent and EndpointAgentUpdater both reported Stopped with PID 0,
and the Setup observer was disabled. Support remained running and its SSH
daemon listened on 127.0.0.1:22222. The existing global sshd kept its PID.
The original service modes and states were restored, including the updater's
prior Manual/Stopped state. The observer returned ready on 3.2.192. The
temporary lease used the existing approved principal and key. The prior
expiry was restored, and Endpoint reported the tunnel closed at 14:36:36Z.
Endpoint received a fresh UserSensor sample after services were restored.

## Windows 10 source availability

At 14:37:39Z, A1-OHTRUD-S1W (.144), C1-MUNZAK-S2 (.170),
A2-PRIEMN-S1 (.207), and A2-MUNSLU-S1 (.146) still had no live WSS
session. All four had Windows 10 build 19045 and last reported Core and
Foundation 3.2.177. The three alternatives did not reconnect or answer a
local reachability probe after a second Wake-on-LAN attempt. The reachable
MUNSLU-S2 (.2) was running Windows 11 build
26100 with 3.2.177 and its existing external global sshd.

## Direct Windows 10 update on VM 126

VM 126 on pve1 installed Windows 10 Enterprise Evaluation 22H2, build 19045,
from the Microsoft ISO. The downloaded SHA-256 matched Microsoft's published
digest. The VM used a real local desktop session. The existing corporate
signing CA was added to the clean guest so the unmodified 177 installer could
pass Authenticode. Setup 177 installed with exit 0 at 15:24:34Z, registered
`7ef51b73-670c-433b-a8e8-a299533c4193` at 192.168.101.79, and reported
Core/Foundation 3.2.177, ready observer 1.0.7, and Support 1.0.1. Support 1.0.1
already reported `tunnel_failed` before the update.

Console assigned exact Setup 192 at 15:25:53Z. Assignment
`50e660f2-d45b-4e19-97a4-ca7bbf3c1573`, attempt
`11bd5008-7071-44fc-8a75-717b5603d763`, went directly from
Core/Foundation 3.2.177 to 3.2.192. At 15:36:47Z it reached APPLIED,
native exit 0, with the signed MSI and source, all four retained private
materials, six stable samples over 182.303 seconds, and one genuine
UserSensor. Observer 1.0.8 was ready at 15:37:22Z. Inventory collected at
15:37:37Z confirmed ENDPT-W10-192, Windows 19045 x86_64, with no warnings.
UserSensor supplied fresh telemetry after acceptance.

Support did not upgrade. Setup recorded `support_install_failed` at
15:33:30Z and the server still received Support 1.0.1. The read-only
guest inspection found OpenSSH Client installed, OpenSSH Server absent,
both CBS and Windows Update restart markers present, and no Support
servicing receipt. DISM logged capability queries during the attempt.
The first Setup receipt retained only a generic code. A signed diagnostic
from the frozen 3.2.192 source reproduced the failure on VM 126 and captured
`support_dependency_reboot_required` from `WindowsFOD.write_receipt`.
The guard stopped the operation before any attempt to install OpenSSH
Server. The old Support image and configuration remained available.
The separate VM 100 SSH proof above is prior evidence.

The first direct native update passed. Its Support acceptance failed.
Production policy 17 still targeted 3.2.189 at this checkpoint and the
published download was 3.2.177.

## Restore the Windows 10 source for a repeat

VM 126 restarted to complete Windows servicing. Both restart markers cleared
and OpenSSH Server remained absent. The signed native 192 uninstall returned
0 at 15:48:04Z and preserved all four private files byte for byte. Setup 177
restored the same device registration with exit 10 (repaired) at 15:50:21Z.
Endpoint confirmed Core/Foundation 3.2.177, observer 1.0.7 and Support 1.0.1.
Windows Update started installing KB5066791 while the baseline was being
restored. CBS set its restart marker during that operation.

CBS session `31289844_1637238392` finalized KB5066791 with `S_OK` and
requested a restart at 16:05:12Z. After the restart, both pending-reboot
markers were absent, OpenSSH Server was still absent, and the restored
3.2.177 observer and UserSensor reported fresh evidence.

The second assignment `c4e76365-d219-488e-ae48-24afa6e5d6eb`, attempt
`caa5fce0-9f09-448c-b739-aa021ecbe518`, went directly from 3.2.177 to
3.2.192. The installer provisioned Windows OpenSSH Server through the
capability API. CBS finished with `S_OK` at 16:22:49Z. Servicing operation
`7e87d9091af6443aa9189eaaa6704b3c` recorded completion, preserved its
firewall boundary, and needed no restart. The new Windows port 22 allow
rule was disabled and global `sshd` remained Stopped/Manual. Support
1.1.6 reported once, then activation restored 1.0.1 at 16:24:48Z. The
workgroup VM could not resolve the assigned domain support account.
Its SSH gateway was reachable and the existing local lab administrator
had administrator rights. The assignment reached APPLIED at 16:28:13Z
with native exit 0, private identity preserved, six samples over 183.216
seconds, and one genuine UserSensor.

The third source restore again preserved the four private files. The
ordinary uninstall returned 0 at 16:30:03Z. The standard Windows
capability removal on VM 126 returned 0 at 16:30:59Z and left OpenSSH
Server absent. Setup 177 completed its retained-identity reinstall at
16:33:12Z. Only VM 126's support policy was changed to its existing
local administrator and the same approved operator key, with a one-hour
expiry. A pinned SSH connection executed an authenticated administrator
command on the matching device at 16:35:00Z. The third direct assignment
`7b9423f8-d856-4232-9f91-a082ab20d7eb`, attempt
`5996c18d-461d-4274-8d5b-f304f45e3eeb`, was assigned at 16:35:36Z
with Windows servicing clear and genuine source UserSensor evidence.

In the third assignment, native Setup accepted Core/Foundation 3.2.192
and provisioned OpenSSH Server without operator changes to Windows during
the assignment. CBS session `31289852_2652548116` finalized with `S_OK`
at 16:50:00Z and requested no reboot. Servicing operation
`f1127fc9343b43069111d3488e6542ff` recorded completion and a preserved
firewall boundary. The new port 22 allow rule was disabled and global
`sshd` was Stopped. Endpoint received the Support 1.1.6 report without
an error. A pinned SSH connection to the updated Support runtime executed
an authenticated administrator command at 16:51:18Z, returning the exact
guest UUID and the signed 1.1.6 image digest.

The third assignment reached APPLIED at 16:53:30Z, native exit 0, with
the expected 192 Core/Foundation, signed MSI and source, all four private
materials, six stable samples over 182.174 seconds, and one genuine
UserSensor. At 16:53:59Z a separate pinned SSH connection again executed
an administrator command on the exact device with both agent services
Stopped and the Setup observer disabled. Support remained Running with
the same PID through service restoration. The agent returned to
Auto/Running, the updater to Manual/Stopped, and the observer reported
ready as 1.0.8. Endpoint received another UserSensor observation after
restoration at 16:55:05Z. The temporary VM lease retains its original
17:33:42Z expiry. A requested inventory refresh at 16:59:34Z confirmed
Windows 10 build 19045, x86_64, with no warnings. The unchanged content
reused its existing snapshot ID. VM 100 was untouched in this repeat.

## Qualification and automatic Windows updates

Endpoint qualified exact 192 from Foundation 3.2.177 using the third
assignment. Qualification `2bd2dc24-164f-4f0e-bb8d-0ea368a0d51e`
expires on 2026-12-11 at 16:54:42Z.

The all-active preview contained one ready device. The only connected
3.2.177 source was MUNSLU-S2 (.2), with Windows 11 and a foreign global
OpenSSH service. Setup protects that service, and its transition to the
Windows capability is unverified. The fleet policy was scoped to the four
known Windows 10 devices on source 3.2.177. The selected preview checked
four devices, all awaiting fresh WSS, with two available slots. Policy 18
was saved enabled at 16:55:29Z, target
`2bfa120d-b182-41b5-ae98-f3354638e96c`, selected scope, maximum two
concurrent chains. The selected devices are A1-OHTRUD-S1W (.144),
A2-MUNSLU-S1 (.146), C1-MUNZAK-S2 (.170), and A2-PRIEMN-S1 (.207).
They can receive automatic assignments after reconnect and source
admission. Policy 18 replaces the prior automatic 189 target. Other
device IDs and source versions are outside this policy.

## Primary Windows download

The canonical publisher promoted the existing immutable installer row
`7aaa9dc6-332a-4caf-a404-a40ed5508d84` and added 3.2.192 to the existing
Windows AUTO enrollment campaign. A server readback at 16:58:14Z confirmed
the primary and the campaign allowlist. The actual Console download was
167,018,248 bytes, SHA-256
`b2552b0c46b31d93821679fd41188dd7324e4830f98aee300a772eaa223239b9`,
with Valid timestamped Authenticode and the expected publisher
thumbprint. Linux 3.2.183 remains the primary native kit.
