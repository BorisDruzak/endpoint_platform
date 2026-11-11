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
UserSensor and activity arrived after APPLIED. This proves normal activation
on test120. The retry path was exercised by automated tests. The pre-existing
SSH grant was expired, so the live 192 check covered Support activation
and reporting. The earlier 191 receipt contains the independent SSH test.

## Windows 10 source availability

At 14:28:54Z, A1-OHTRUD-S1W (.144), C1-MUNZAK-S2 (.170),
A2-PRIEMN-S1 (.207), and A2-MUNSLU-S1 (.146) still had no live WSS
session. All four had Windows 10 build 19045 and last reported Core and
Foundation 3.2.177. The three alternatives did not reconnect after
Wake-on-LAN. The reachable MUNSLU-S2 (.2) was running Windows 11 build
26100 with 3.2.177 and its existing external global sshd.

No direct 177-to-192 Windows 10 test or source qualification was completed.
Policy revision 17 continued targeting 3.2.189 under its existing source
qualifications. No automatic assignments to 3.2.192 were enabled.
Windows 3.2.177 remained the published download.
