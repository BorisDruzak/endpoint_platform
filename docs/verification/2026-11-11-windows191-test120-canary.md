# Windows Setup 191 candidate on test120

Setup 191 includes the exact Windows 10 OpenSSH rule fix
`a45435145ef22be415c601b836addf9a6215cb52`. The runtime version is 3.2.191,
and the separate Support component version is 1.1.5. The frozen runtime tree
and installer sources match the immutable binding. Setup EXE, MSI and the
embedded Support image have valid signatures with timestamps. The embedded
Support code matches the reviewed source. No portable OpenSSH Preview is
bundled. Production registered the exact artifact as a candidate. Its public
download flag is false. The Windows primary download remains 3.2.177.

The PowerShell 5.1 FoD, Support, and lifecycle suite passed 144 tests.
The Setup bootstrap, staged payload, self-check, server policy and assignment
suite passed 91 tests. The production setup policy remained revision 17,
targeting 3.2.189.

## Live result

Production assigned Setup 191 only to test120, DESKTOP-9ST5HO2. The
assignment `4dd93c38-249f-4f21-a740-28755dd35c62` started from
Foundation 3.2.189, Core 3.2.190, and observer 1.0.8. The host ran
Windows 11 build 26100 with both Windows OpenSSH capabilities already present.
It reached APPLIED at 13:23:45Z with native exit 0, all four private materials
preserved, six observations over 185.362 seconds, and one genuine UserSensor.
The production observer reported ready Core/Foundation 3.2.191.
Inventory collected at 13:25:25Z showed Windows x86_64 without warnings.

The installer reported `support_install_failed` at 13:20:26Z. The active
image and configuration reverted to Support 1.1.4. The exact signed
Support 1.1.5 image was present in the Agent directory. After APPLIED,
a separate signed diagnostic invoked the same Support activation implementation
as SYSTEM and passed dependency validation, service stop and start, and
initialized readiness. The frozen 1.1.5 service reported to Endpoint.
This did not reproduce the first activation failure, whose precise exception
remains unknown. The diagnostic task was removed. MSI was not replayed.

A key-authenticated command through the independent, UUID-pinned tunnel
passed at 13:29:28Z while EndpointAgent and EndpointAgentUpdater were stopped
and the Setup observer was disabled. The Support process stayed running, and
its SSH daemon listened on `127.0.0.1:22222`. The pre-existing global sshd
kept PID 3116 and its prior service mode. The test restored the previous
agent, updater and observer states and ended the temporary diagnostic lease.
At 13:30:53Z the observer was ready, UserSensor had delivered a new sample
after restoration, and Support 1.1.5 reported without an active tunnel.

## Remaining qualification

The direct source 3.2.177 Windows 10 path was unavailable. A2-MUNSLU-S1
(.146) did not reconnect after Wake-on-LAN, and the other known Windows 10
source 177 devices were offline. MUNSLU-S2 (.2) was online with 177 and
Windows 11. Its Windows Server OpenSSH capability was absent while a separate
global sshd service ran from `C:\Program Files\OpenSSH\sshd.exe`. The
candidate preserves that pre-existing service boundary. No Setup was assigned
to .2. Its temporary read-only diagnostic lease was closed.

No source qualification was created for Setup 191. The observed 120 outcome
covers the native update, user telemetry, inventory, and SSH after the separate
Support activation. Unattended Support activation and a direct Windows 10
177-to-191 transition remain required before promotion and automatic delivery.
