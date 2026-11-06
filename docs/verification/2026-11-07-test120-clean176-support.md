# Clean Setup176 and automatic service access on test120

Result: **native removal, clean installation and independent administrator access
passed; complete user telemetry failed**. This is a real workstation test, not the
earlier API/PostgreSQL fixture. No new Windows release or native-source fleet
qualification was created. Windows primary176 and Linux156 remain unchanged.

Times below are UTC on2026-11-06; operator local time is UTC+5 on2026-11-07.
Final service-access acceptance was20:04:10UTC /01:04:10 Asia/Yekaterinburg.

## Scope and protected state

The user explicitly requested complete removal on192.168.101.120, followed by
clean installation and service-access verification. Fresh strict direct SSH proved
`DESKTOP-9ST5HO2`, administrator `test_agent_win`, sosnadmin.local membership,
active ordinary-user RDP session2 and no native installer process/active fleet
chain. The existing Windows SSH service was retained throughout, PID3564. Domain,
GPOs, accounts, passwords, other PCs and gateway configuration were not changed.

Current provider was783cc21589e80115d395c4be8b89e710687804e6/schema0047,
with automatic installation defaults enabled for existing `SOSNADM\admin-2`
and the already-approved operator public key. Exact domain SID7188 was resolved
before removal; no administrator was guessed or created.

## Removal and genuinely empty baseline

The exact trusted176 MSI and its release manifest were staged outside product
roots, with the canonical Uninstall wrapper matching packaging commitbe3ea714.
Actual local/remote digests, Valid publisher4D signatures and timestamps were
checked before execution. A one-shot SYSTEM driver ran the ordinary authenticated
native wrapper with `-Operation Uninstall`; no direct MSI bypass or replay occurred.

- Uninstall started19:41:10.072016UTC, finished19:42:20.606747UTC: wrapper/native0,
  SYSTEM SID18, completed task result0.
- Product registration, all Endpoint services, active Support executable/state
  and managed executable processes were absent; native transaction fence absent.
- The component actually unregistered its old authority at19:42:02.492868UTC:
  old Support disabled/revoked, installedfalse and tunnel false.
- The remaining official observer task was matched to its exact1.0.7 path and
  SHA8a1a30e7d208fbb431e2f715967d8a21eb82eac43edbfb4e97433a83049a6247,
  exported and removed only after idle/native completion proof.
- At19:45:29.957077UTC the clean baseline proved **zero managed services/tasks**,
  no product registration, no old identity/Support state and no native fence.
  All four active roots were absent: Program Files/Endpoint Platform,
  ProgramData/Endpoint Platform, Program Files/EndpointPlatformSetupUpdater and
  ProgramData/EndpointPlatformSetupUpdates. Product-owned Endpoint registry keys
  were exported and removed after settlement.

Residual old roots/history were moved into the protected SYSTEM/Administrators
archive `C:\Temp\EndpointClean176-20261107\retained-*`, outside every active
installation root; ACLs were reset under its protected parent. Nothing from that
archive was restored or used for enrollment. This preserves old native failure
history without reusing old credentials, keys, selectors or updater state. No
Windows Installer global cache, unknown native journal or foreign product was
deleted. An initial task-ownership guard correctly rejected an assumed observer
location; its actual separate code/state roots were then verified from source.

Old Device943c87ef-f121-40b9-a31f-003e9459e292 was retired at19:46:12.945817UTC;
its sole active source credential1dea0f8e-97c3-4fef-8a05-7ab1d0a9e49d was revoked
in the same audited transaction. Support had already unregistered itself. Old
device, enrollment, qualifications, assignments and failed-attempt history remain.

## New installation and automatic authorization

The unchanged signed176 EXE ran once as SYSTEM with`--quiet`:
19:46:37.710876UTC to19:49:08.029648UTC, Setup exit0, durable
`COMPLETED/SERVICE/SERVICE_RUNNING`, no remaining native fence.

Request6e27c9db-3798-473d-84ab-ed0d62f875a4 was genuinely created by that Setup
at19:48:07.382211UTC from192.168.101.120. Existing hardware history intentionally
produced`review_required/DUPLICATE_IDENTITY`. The operator verified exact hostname,
source,176 release, sole existing AUTO campaign and a server-side matching
fingerprint against the retired device, then used the canonical approval API.
That enrollment approval is distinct from support policy authorization; it was
not an exception to source checks or an automatic fresh-PC enrollment proof.

New Device **06143264-1b7b-42e7-990f-7f8e1292491b** enrolled with new device
credential, independent source identity, host key and tunnel key. Both local
credential/identity file digests differed from the archived old installation.
Core and Foundation are176/source03143de5005201837c58a2f0955d714e7026a2eb;
Foundation product019D6BCB, MSI SHAcb9011259f964aba3262f407e502f4c5781df774023f4103d89fe758eac1d32e
and canonical119file tree30d577c243ed567613a5962a9ab84b5f3f9efd986022d8983183bde51979a699
matched the sealed release. Setup client1.0.7 reported ready and matching versions.

Actual immutable audit records prove exactly one pending event at19:48:56.276367,
then exactly one automatic grant at19:48:57.624738, both device-attributed. Pending
revision1 became revision2/generation1; no manual policy-change event exists.
The first healthy independent Support1.0.1 status granted the initial eight hours,
ending **2026-11-07T03:48:57.612997Z**, or **07.11 08:48:57 Yekaterinburg**.
Later polls and tests did not renew it. This closes the earlier missing real
first-install service-access test; it does not close user telemetry acceptance.

## Actual administrator commands with Core/updater unavailable

Authenticated Endpoint card supplied the new UUID, host public key and gateway
loopback port **32006** together. `Connect-EndpointSupport.ps1` used strict gateway
verification and a new UUID-specific device pin; the old UUID pin was retained.

At19:50:28UTC actual SSH proved hostnameDESKTOP-9ST5HO2, existing
`SOSNADM\admin-2`, exact domain SID ending7188 and administrator membership.
Support was Auto/Running PID9680, immutable1.0.1 SHA
224cbee71d3bc5f1151cc21491f36e7ba09eb87dfef9a10b082569243a61667e.

Fault injection saved the original state, disabled the idle official observer task
and stopped Core. Updater was already Manual/Stopped and remained so. Real SSH
commands at19:52:41.574701 and19:54:18.197435UTC were **96.622734 seconds apart**,
with CoreStopped, UpdaterStopped and observerDisabled. Both proved the same domain
administrator and Support PID9680/unchanged executable. Independent API status
at19:53:58.453260 stayed fresh, healthy and connected while ordinary presence was
offline. No Core heartbeat, updater task or cached policy was substituted for SSH.

Finally restoration at19:54:21.794446UTC returned CoreAuto/Running, observer enabled
and UpdaterManual/Stopped; Support remainedPID9680. Subsequent genuine WSS and
ready1.0.7 hello advanced. Actual SSH was attested through the canonical API at
20:04:32.973089UTC without changing policy/expiry or claiming session recording.

## Failed supplemental user-telemetry check

Do **not** call this a fully accepted clean agent installation. The ordinary user
session remained Active, native restoration launched UserSensor PID11704 in
session2, and the agent's local activity listener wasREADY. Nevertheless the new
device's `policy_sensor_health_current.user_sensor_last_seen_at` remainedNULL;
no accepted user samples/activity were established. Other local source states and
fresh WSS are not replacements for those samples.

Read-only diagnosis confirmed the correct new protected MSI-bound sensor bytes,
proper LocalService/UNRESTRICTED service SID, expected named pipes and active
session. The sensor EXE is individually NotSigned but exactly matches the trusted
MSI-owned SHA f26db2f11208d9114c0dfd0e4129adf96cd576c80de198605f7975a4d418a21f;
it must not be described as individually Authenticode-signed.

A bounded restart of only that identified sensor through the existing ordinary
user's limited interactive token created PID6260 at20:01:03. It did not fix the
failure: fresh health at20:03:24.639505 still hadNULL user_sensor_last_seen_at.
No credentials, ACLs, IPC authorization or native state were changed to conceal
the problem. The precise rejection/hang cause is not established. The original
full-acceptance check remains failed; a separate service-access check records its
pass and this explicit telemetry failure. Unattended fresh user telemetry remains
unqualified and requires separate correction; prior accepted update profiles and
the independently verified support channel are separate evidence.

This check was performed after the controlled Core stop/restart. Accepted sensor
timestamps immediately before that fault were not separately captured, so these
facts cannot attribute the failure specifically to initial installation instead
of recovery after Core restart. The named-pipe client/server cause remains open;
no live access-control workaround or binary replacement was attempted.

## Preservation, cleanup and remaining state

All five other previously existing stored Support policies/keys/expiries were
compared unchanged. Fleet policy10 retained enabled/all_active/max2 with no frozen
UUID list and active chains0. Sole AUTO retained its eleven versions,
192.168.101.0/24, quota100,2030-09-27 expiry; usage increased exactly6to7 for this
new enrollment. Provider/schema, Windows176 signed bytes and Linux156 were not
changed or rebuilt. No new fleet source qualification was asserted.

Only the official observer task remains. Temporary uninstall/install/sensor-restart
task registrations were removed after exact ownership/result checks; no running
sensor process was stopped during task-registration cleanup, and PID6260 remained.
Protected local staging/history remain available for investigation. Only task
admin sessionR11 was revoked at20:09:44.589103UTC and redacted after final API checks; no Support lease or
other administrator session is revoked. GitNexus was unavailable; runtime, sealed
source, canonical APIs and direct evidence were used without reindex/sync.

Verification artifacts in this worktree's ignored
`.superpowers/sdd/2026-11-07-test120-clean176/` include before/empty-baseline/native
results, canonical automatic audit, both stopped-service SSH challenges,
restoration, failed full-telemetry acceptance diagnostics, separate successful
service-access acceptance and session/task cleanup receipts. No new pytest suite,
code build or source qualification was claimed for this operational test.
`validate_docs.py` checked JSON consistency, unchanged release/media/fleet fields,
explicit telemetry failure and the updated live connection example;
`git diff --check` passed. The documentation commit includes exactly `AGENTS.md`,
both current/176 release records, the support runbook and this verification file.
