# Linux 181 native canary: ongoing acceptance

Status: signed 181 installed on VM 107 with native 0 and outer Setup 0. Full
lifecycle, final stability and publication gates are still in progress. Linux
primary remains 156; Windows 177 publication and production policy are unchanged.

Source: `83e3bfce3ad82a774f7ae84585d0ddb213c2d32a`.
Commit: `fix(linux): bind retained setup to the frozen runtime version`.

The retained coordinator now accepts only component `setup` with the same build's
tracked `AGENT_VERSION`. Modern signed source/Setup/digest matching and the exact
immutable historical 156 exception remain unchanged. The new behavioral tests
first reproduced both faults: current 181 rejected and stale 179 accepted. The
correction passed those tests, independent review, and additional missing/stale
identity probes. No code or artifact was substituted into signed 180.

Root's final focused Windows command returned **70 passed, 14 POSIX skips**;
shell syntax, complete diff and exact 11-file staged hash checks passed. On actual
ALT Python 3.12.13 the executor, coordinator, staging-configuration and native
packaging suites returned **126 passed, 1 built-RPM skip**. The subsequent actual
built-RPM probe passed: **127 passes across split runs**. Three warnings concern
unused asyncio settings in the minimal isolated pytest environment. The SSH
startup code and native harness were byte-identical to the previously accepted
180 isolated regression; that unchanged harness was not repeated.

The native build completed at 12:03:03.435326Z with commands `[0, 0]`, clean source
and unchanged installed Core/updater PIDs. Both final RPM signatures and complete
payload/source bindings were verified on ALT and independently on staging. The
kit and manifest were detached-signed with the existing publisher. Staging's
mandatory native verifier registered source
`a523e0f1-dee4-4be0-8668-50619fe65f57` at 12:09:00.297279Z. Publication of this
candidate row is separate from installed or fleet acceptance.

## Actual frozen retained entry and upgrade

Before any native 181 transaction, the actual frozen Setup executed `notify`
through its retained private image. It returned **0** at 12:06:04.671574Z. Its
retained record matched version 181, source 83e3bfce and Setup SHA256
`095d6ddc6a22bc0e1c74215e4873be4911ac8973a41dd5cdc9b237d0dc292147`.
The existing 179 operation journal, runtime-ready marker, all four private files
and Core/updater/Support PIDs were unchanged. This smoke test invoked no RPM.

The real 179-to-181 operation ran from 12:10:46.876450Z to 12:11:14.940953Z.
Operation `9febbf10-4c6e-4912-be42-335b27884d0a` has native exit **0**, settled
state and completed bootstrap/registration. The outer Setup returned **0**.
Exact installed packages are Core and UserSensor `3.2.181-alt6.x86_64`.
Sequence 2 was acknowledged on the original generation
`03d2c75c-186c-4586-9532-08f1160c6b7a` and original device
`29a8bed4-2894-40f7-89fb-07b3c7f633fe`; both prior installed events remain.

Credential, identity, configuration and CA retained their original exact digest,
owner, group, mode and size. `rpm -V` for both packages returned 0 with no output.
Core PID 572618 and Support PID 572611 initially had zero restarts. The installed
retry timer was inactive after completion; its one-shot service retained a prior
exit-code failure, which is preserved separately and is not a native failure.

The original KDE X11 session 6, UID 1000, remained active. New probe PID 572326
was observed. Staging accepted UserSensor time 12:13:11.068252Z in health received
at 12:13:15.600206Z, with the activity listener `READY`.

## Independent access checkpoint

An actual strict UUID-pinned SSH command through the ordinary staging bastion
returned 0 and UID 0 at 12:11:57Z. It verified the VM product UUID, installed
Support source and binary SHA256
`9712c68d687b8c46f06bff95513382298f4a3816049eede22328d08ad28d9b50`.
The existing root account, operator key and device host pin were used. Ordinary
SSH, PAM, sudo and the user's session were not reconfigured.

Core, updater and its path watcher were explicitly stopped at 12:14:29.784442Z.
The first stopped-state root SSH command succeeded at 12:14:31.806499Z, BOOTTIME
101402.789835522. It measured Core/updater PIDs 0, inactive path watcher and the
same active Support PID 572611 with unchanged source/binary bytes. At 12:15:21Z,
the server still reported a connected tunnel and a fresh independent Support
status after the Core WSS session closed. The original revision 2/generation 1
deadline remained **2026-11-08T19:18:32.175239Z**; upgrade did not renew access.

The second command succeeded at 12:16:31.083205Z, BOOTTIME 101522.066544012:
**119.276708490 seconds apart**. Both commands measured stopped Core/updater and
watcher, UID 0, the same active Support/tunnel PIDs and identical binary/source.
The owned fallback timer was stopped afterwards, and only the original active
Core/path units were restored at 12:16:32.963899Z. Support was not restarted.

At 12:20:56.697248Z the restored Core PID 574191 had been stable for **263.526
BOOTTIME seconds**. Its restart count and the exact restored unit states remained
unchanged; private files and `rpm -V` still matched. Staging accepted UserSensor
time 12:20:31.070911Z and fresh Activity, with `READY`, a connected tunnel and the
original access deadline.

## Historical rollback checkpoint

The exact immutable 156 Core/Sensor archives and original detached kit manifest
were supplied to retained Setup 181. The actual rollback ran from
12:22:02.320274Z to 12:22:24.411122Z. Operation
`1e570209-bd5f-4a77-bd73-48bf7cbb88c9` returned native **0** and outer **0**;
bootstrap completed and sequence 3 was acknowledged on the same card/generation.
The four private files remained unchanged. KDE session 6 stayed active and probe
PID 577205 was observed under UID 1000.

Historical 156 contains no independent Support service. The actual units were
absent, the server reported Support unavailable and the strict SSH attempt was
refused at the gateway loopback port. Stored access still had its original
deadline. No running reserve channel is claimed while 156 is installed.

## Return, ordinary removal and reinstallation

The real 156-to-181 return ran from 12:24:34.646620Z to 12:25:02.266631Z.
Operation `94a74edd-62c3-4c0d-8ace-48dc0d1e6a63` returned native **0** and outer
**0**, with completed bootstrap/registration and sequence 4 acknowledged on the
original card/generation. All four private files were unchanged. The same KDE
session remained active, and staging accepted a new UserSensor sample at
12:25:59Z with `READY`. A real pinned root SSH command succeeded at 12:26:35Z.

Ordinary removal ran from 12:27:54.295471Z to 12:28:15.668067Z. Operation
`47ff125e-049c-4959-a5ca-e1c4a060abed` returned native **0**, outer **0** and
acknowledged sequence 5. Support and browser cleanup were complete. Both RPMs,
runtime-ready marker, product services and background sender were absent;
Support's private directory retained only its lock. Credential, identity,
configuration, CA and protected lifecycle journal remained.

Ordinary reinstall ran from 12:30:44.695882Z to 12:31:09.601369Z. Operation
`667df8d1-671e-414c-8dfc-62dc49ec6e89` returned native **0** and outer **0**,
completed bootstrap/registration and acknowledged sequence 6 on the same card
and generation. Its predecessor is the real removal event. All private files
remained unchanged. Core PID 583132 and Support PID 583125 had zero restarts;
staging accepted fresh UserSensor time 12:35:09Z with `READY`.

Removal erased the former Support keys. The original strict host pin correctly
rejected the new SSH host key. Before updating the owned canary pin, the operator
verified genuine removed/installed events, original device/generation, unchanged
operator key/port/deadline and an authenticated staging public registration
matching public-key derivation from the actual VM's root-owned private host key.
Only the canary-specific known-host file was changed; the old pin was archived.
Pinned root SSH then succeeded at 12:32:52Z. Support revision 4/generation 3
retained the original **19:18:32.175239Z** deadline; reinstall did not renew it.

## Offline removal and reinstallation

Only VM 107's route to staging `192.168.101.118/32` was temporarily blocked with
an owned unreachable route, metric 60981. Before mutation, the exact route was
absent and a five-minute automatic restoration timer was installed. The test
changed no default route, firewall, DNS, TLS, AD or ordinary SSH configuration.

Offline removal ran from 12:39:09.340652Z to 12:39:30.974858Z. Operation
`bbc3192a-fe97-4d75-9e48-6192d0a41167` returned native **0** and outer **21**:
native removal was settled while server delivery remained pending. Sequence 7
was queued with acknowledgement still at 6. Both packages and product services
were absent, private identity was unchanged, and no background sender remained.
Support cleanup truthfully recorded **incomplete**, since unregister could not
reach staging; local Support keys were erased. Browser cleanup was complete.

While still offline, reinstall ran from 12:39:42.991812Z to 12:40:07.187074Z.
Operation `8ecc1276-a7cd-4aca-a2a8-1b73206211d6` returned native **0**, outer
**21**, settled RPM installation and pending bootstrap. Exact 181 Core/Sensor
packages were installed; sequence 8 was queued behind 7 with acknowledgement 6.
Core, updater, path watcher and Support remained inactive pending registration.
All four original private files were unchanged.

At **12:40:28.041650Z**, the owned route was removed and its restoration timer
stopped; the exact route returned to its empty baseline. The installed retry
service was triggered for reconciliation, with **no second RPM invocation**.
Staging received removed sequence 7 at **12:40:35.985157Z**, then installed
sequence 8 at **12:40:36.029261Z**, with exact predecessor links to sequence 6
and then 7. The original card/generation reached **8 acknowledged of 8** and
bootstrap/registration completed. The immutable removed event still reports
Support cleanup **incomplete**; successful later delivery did not rewrite it.

At 12:44:32.722872Z, actual Core PID 588903, Support PID 588895, dedicated sshd
PID 589026 and tunnel PID 589028 were active with zero restarts. Updater was
inactive, its path watcher active, and retry service/timer inactive with success.
`rpm -V` returned **0**, empty output, and all four private files matched.
Staging accepted UserSensor time **12:44:34.073201Z**, `READY`, in health received
at 12:44:38.569340Z, and fresh Activity time 12:45:19.069157Z. KDE session 6
remained active. The probe executable is sampled briefly; its absence in one
process snapshot is not evidence that fresh accepted user telemetry stopped.

The old generation-3 strict pin rejected offline-reinstalled host keys with SSH
**255**, before command execution. Genuine sequences 7/8 and authenticated staging
registration were verified against trusted VM public-key derivation before the
owned pin was rotated and its predecessor archived. Support now has revision
5/generation 4, still with the original expiry. A real strict pinned SSH command
at **12:46:26.653209Z** returned **0**, UID **0**, the exact VM UUID and unchanged
181 Support source/binary. Core/Support/tunnel PIDs still matched the earlier
post-reconciliation observation and all restart counts were zero.

## Remaining acceptance gates

Full-clean new registration and approved historical-parent linkage, actual
administrative disable/revoke/short-expiry/recovery, final end-to-end stability
and publication remain incomplete. A legitimate current staging Console admin
session is required for those admin actions. The available browser still shows
the login page; the user's promised login has not yet been observed. No admin
account, password or session was fabricated or reset. Production is unchanged.
