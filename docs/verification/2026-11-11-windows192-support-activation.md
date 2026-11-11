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
These observations do not identify the exact exception behind the generic
Support result. The test used VM 126 only. The separate VM 100 SSH proof
above is prior evidence.

The direct native update passed. The complete Windows 10 release test
remains failed at Support activation. No 3.2.192 qualification or fleet
policy change was made. Production policy 17 still targets 3.2.189 under
its existing source qualifications, and the published download remains 3.2.177.
