# A2-INFAN-N full156 to158 through Endpoint

Status: initial server-only attempt blocked before Core download. After explicit
user authorization, a one-time owner-only administrative repair completed at
05:10:26Z and the same Endpoint chain resumed05:12:02Z. Full158 applied05:25:49Z
with native exit0,181.622 seconds of stable observation and fresh user telemetry.
This is an administratively prepared continuation, not an unattended-source pass.

The user authorized a full update only on192.168.101.29 and verification of its
result and telemetry, without workstation preparation. Known Yandex browser
telemetry was previously deferred by the user and is not claimed as passed.

## Exact source and authority

Device dd5ebcfc-2e47-4d2b-ab29-85c689028b24, hostname A2-INFAN-N, authenticated
source192.168.101.29. Original physical inventory UUID
D09CEC00-C07E-11EC-9CE2-9A47AAD22C00; this is a workplace PC, not a disposable VM
despite its Temporary installer150 enrollment label. Source Core/Foundation156,
fresh matching WSS and no conflicting Core/native operation. No Setup-client
presence existed before this assignment. During the initial server-only attempt,
no workstation SSH, SMB staging, remote
Windows command/task, ACL repair or manually installed updater was used.

Pre-update health collectioneaadaa37-a27d-4896-8535-76e2db1a8433 and inventory
collection93fa3cd2-0559-42ef-b7f2-af2d17e06e22 completed through Endpoint at
04:22:48Z. UserSensor data and activity were fresh. Activity/security spool/USB/print
sourcesREADY; Chrome/Yandex were CLOSED, Endpoint policyAPPLIED/native hostREADY.
These browser policy facts do not demonstrate extension heartbeat or browser data.

Server remains d3459936a25114b56335aaebf5a4d209833cb3aa/schema0045.
General fleet policy remains disabled/max_parallel1. The server's canonical
request_setup function created only this Device's audited preparation at
04:23:24.509402Z, actor ssh-osn-admin/requesttest29-full158-20261105:

- Preparation403f9fce-7f6c-4943-a8f2-49eb2ea4448c.
- Core163 bridge rollout4a38e1c1-cd24-4924-b8b1-665765eae210.
- Planned exact compatible Core155 return; no weakening of Core157 minimum.
- Full Setup releaseb06ce3dd-49ea-4202-aa55-d446e0dacc6b,
  endpoint-windows-full-setup-3.2.158-r3-5cb267d.

## Immutable target

Exact158-r3 Setup SHA256
3a603f2440bf501b85032e0defcdb8123efb5bdb31c1a7d4ed87433fcf7f7bb2,
145929792 bytes. Native source9423d9c27ea6b2d6c544c1bcdc1edb7cc9d15421,
MSI SHA256b7d3ccebdeb5db1bc0b10af14923244c96b1debb3d1ff78cb4e8c062fe56d1a1.
Signed observer1.0.5 is delivered by immutable Core163
b59ac4e6-9c52-4d56-9294-8a791feba25b, ZIP SHA256
119dc8152289f1bd057ad84a780699c445df9846cb492a325ea6801c89991a5e.
The exact156 source profile was qualified on test120, qualification
872a53bc-17f3-48ac-a481-dfeaaac2f961. This operation creates no new build or primary
publication and does not modify that canary's receipt.

## Observed preparation barrier

Bridge target acknowledged requested at04:27:02.314102Z. Through04:33Z no client
presence, new Core selector, downloads directory or native Setup assignment
appeared. Read-only SMB inspection showed only the pre-existing
staged-trial-proof.json in updates. Source selector remained156/source6ed41cd.
SCM QueryServiceConfig independently confirmed NT AUTHORITY\LocalService.

The existing updates directory owner is BUILTIN\Administrators (S-1-5-32-544),
with protected fixed DACL: SYSTEM/Administrators full access and the two agent
service SIDs modify0x13019f. Those service rights do not include WRITE_DAC.
Core156's exact frozen source6ed41cd unconditionally calls
PyWin32AclAdapter.protect_update_path(updates_root) after the requested ACK and
before creating downloads/downloading the ZIP. That calls SetNamedSecurityInfo
to replace DACL. The unprivileged LocalService process is neither directory owner
nor a WRITE_DAC trustee. This is a deterministic authority barrier for this code
path, unlike test120's clean source156 whose stager created its own directory.

The original health reported17,093,050,368 free bytes and warnings=[]; the small
Core ZIP is not blocked by the observed available capacity. No runtime exception
text was retrieved: direct DCOM read-only diagnostics were unavailable. The
diagnosis rests on exact source/account/owner/DACL/control-flow evidence; no
WinError5 log is presented as an observed receipt. No barrier was bypassed.

At04:35:13.833718Z canonical pause_rollout paused only bridge4a38e1c1-cd24-4924-b8b1-665765eae210
after rechecking requested/source156, preparing_client, no client and no native
assignment. A separate operator audit records the reason. The existing target
remains honestly requested and preparation preparing_client; no invented terminal
failed/applied status was written. Pausing recommendations preserves operation
ownership. General fleet remains disabled.

At this initial checkpoint the source was healthy, but this was not an update acceptance. A newer Core
cannot repair this source through the same staging path before being downloaded.
The current installed observer-free Foundation has not demonstrated an independent
privileged Endpoint bootstrap repair channel. No one-time domain/SSH/ACL workaround
had yet been authorized. Do not generalize the clean156 canary to all historical
156 installations merely from version numbers or an eligible preview.

Post-attempt source-health collectionb1595bb4-18be-420a-9cf4-9dfacae1b381 and
inventory333c87bd-e47c-4cc9-8bc2-800d841ffb48 requested via Endpoint. Their final
results are recorded below; these are source checks, not post-install158 proof.

Both completed at04:36:03Z. Health warnings=[]; its service list was empty, so it
does not independently prove all Windows service states. At04:37:28Z matching WSS
was fresh, Core/Foundation remained156 and observer presence/native assignment
remained absent. UserSensor sample04:36:26.615419Z and activity through
04:37:26.656881Z were accepted, interval count36 versus19 at baseline. Activity
listener/security spool/USB/print sourcesREADY. Browser processes remained CLOSED;
no browser heartbeat, physical hardware event or WorkTime employee flow is claimed.
At04:37Z the source remained connected and collecting telemetry; target158 was not accepted.

## Server-only repair feasibility,04:58Z

The user requested checking existing Endpoint channels before connecting to the
workstation. Inspected the installed frozen source6ed41cd, not just current source:

| Existing channel | Finding |
| --- | --- |
| Core recommendation/rollback | Existing156 still stages through updates and rewrites its DACL before any ZIP download; server version/channel/reason cannot replace this installed code |
| Endpoint commands and module recipes | All27 frozen built-ins are bounded read-only/diagnostic/network capabilities; unknown capabilities are rejected. Server recipes compose these built-ins. The legacy Python ModuleManager is not a dynamic package execution path in the headless Endpoint CommandExecutor |
| Privileged EndpointAgentUpdater | Offline worker validates an existing local pending document/archive before extraction and verified candidate execution; it has no independent remote-download or staging-ACL-repair command |
| Privileged EndpointBrowserPolicy | Closed request schema admits only apply/relinquish for chrome/yandex; no filesystem-repair or code-execution action |
| New signed Setup-client bootstrap | setup_update_bootstrap.py is absent from the installed156 source. Its later implementation cannot execute before delivery of a newer Core |

No supported existing server-only repair route was identified. No unsupported
command, recovery journal fabrication, module payload workaround, host permission
change or rollout resume was attempted. At04:58:43Z source remained156/156 with
fresh WSS/user telemetry, bridgepaused, no Setup client and no native assignment.

The fallback is a separately recorded one-device administrative repair of the
verified staging-directory ownership, preserving its exact DACL, private files
and native journals, followed by resumption of the same audited Endpoint chain.
That would be an explicit exception to unattended source preparation, not a claim
that server-only delivery passed. Future source fixes must avoid unnecessary DACL
replacement when an existing trusted directory already has the required policy;
shipping that fix alone does not repair immutable156's delivery barrier.

## Authorized one-time administrative continuation

After checking SSH, the user explicitly instructed proceeding with repair. This
revokes the no-workstation-preparation condition only for the recorded fallback
on A2-INFAN-N/101.29; it is not a new unattended-source qualification.

An authenticated admin-2 SSH session verified exact hostname, hardware UUID,
enrollment Device UUID, installed156/source6ed41cd and LocalService service account.
The guarded inline PowerShell repair held the canonical Global\EndpointPlatform.Agent.UpdateTransaction
mutex with the exact protected five-ACE policy, validated completed compound
history and absence of native/OTA fences, and pinned the parent/target directory
and private files. It used an already-held SeRestorePrivilege temporarily, restoring
its prior state. Only the pinned updates directory's owner changed from
S-1-5-32-544 to S-1-5-19. No recursive edit, DACL/group change, private-file change,
service restart, manual updater installation or native installer launch occurred.
The historical staged-trial-proof.json bytes and permissions were preserved.

Repair completed2026-11-05T05:10:26.1702522Z. Script SHA256
2399fcc35865f3583f17e7150d8cf5d24ebdddb6a147d1eaae65807fa265458c.
A local native probe first verified owner-only mutation, exact DACL/group retention
and original-owner rollback. Script parser validation passed. Independent SMB
postflight verified directory owner/DACL/group and all four private files'
hashes/lengths/owners/SDDL against the pre-repair snapshot. Credentials were used
only for SSH authentication and were not stored in scripts or receipts.

Canonical activate_rollout resumed the exact existing bridge at05:12:02.424746Z.
The generic resume exclusion also sees the child's own preparation. Under the
existing Build→Rollout/Target→Device locks, maintenance therefore used the same
internal handoff pattern as preparation transitions, scoped to this exact bridge
and no native assignment, then restored preparing_client before commit. No
handoff or invented native result was committed; activation and operator-repair
audit events were appended. No new target, rollout or preparation was created.
General fleet policy remains disabled/max_parallel1. Further delivery uses the
existing Endpoint controller and normal poll cadence.

Core163 applied05:13:56.679590Z. Client1.0.5 reported ready from this machine;
independent on-disk verification matched SHA256
5b606fd5d25158be550ba4a6e1a8f82bd203a47e485051b867e63a376da620dd,
AuthenticodeValid/timestamp and fixed publisher4D4C23389F5FF77BC4EB32044761019EAE8FB776.
The controller automatically created return155 rollout
2b1e98e2-26c5-48d2-9187-0f1fe7cee72c at05:14:21.674584Z; it applied05:18:16.679066Z.
No further workstation preparation or manual companion launch was used.

Operator receipts: admin-owner-repair-receipt.json, private-before-adminfix.json
and resume-after-owner-repair.json under the private evidence directory below.

## Completed native158 acceptance

The controller created the full Setup assignment with the same ID as preparation
403f9fce-7f6c-4943-a8f2-49eb2ea4448c. Native attempt
531b3f79-91d3-4e99-aa8a-8d408f1c740e started05:20:20.717897Z, returned actual
exit0 at05:22:42.5526154Z and reached applied05:25:49.563715Z,
safe_code setup_post_restart_confirmed. On-disk job.json independently agrees on
the applied phase, attempt, native exit and soak. No manual native launch/retry,
service restart or companion launch was used after the owner repair.

The accepted proof records Core/Foundation3.2.158, exact native source9423d9c and
MSI SHA256b7d3cceb, accepted native provenance, no pending transaction, restored
companions and all four private-file continuity checks. Six samples cover181.622
seconds: services and companions stable, connected, sensor_count1,
sensor_cpu_percent_max0.0043. This is the measured sensor CPU during the bounded
soak, not a whole-machine performance or long-term workload qualification.

Independent read-only SSH postflight05:24:55Z confirms the installed MSI product
Endpoint Agent3.2.158, current.json version3.2.158/source9423d9c,
EndpointAgent Running/Auto/LocalService and EndpointBrowserPolicy
Running/Auto/LocalSystem. EndpointAgentUpdater is Stopped/Manual/LocalSystem,
consistent with its on-demand role after completion. Sensor and Tray run under
the ordinary user's SID in session1 from the fixed Program Files paths. A second
read-only check05:28:30Z confirms one sensor11996 and Tray parent14536/child12856,
both created during automatic restoration; the one-file PyInstaller tray spec
includes its binaries in EXE, so the two Tray processes form one packaged pair.

Independent private-four comparison after native completion verifies unchanged
hash, length, owner and SDDL for device-credential, enrollment-identity.json,
endpoint-origin and endpoint-ca.crt. Device identity and enrollment are preserved.
New WSS a56768ca-6819-42f4-8ed9-f85d52a91e26 opened05:21:34.944717Z from101.29
and remained fresh after applied. At05:28:33Z, UserSensor accepted sample
05:27:26.022794Z and activity advanced through05:28:26.069633Z,51 intervals
versus19 at baseline. Activity listener/security spool/USB/print sources are READY.

Post-install health cb5bbc8f-b67c-4547-bd8a-b0874e713e43 and inventory
abd98f9b-6c72-4b2c-87c6-fa777a5a1d13 completed through Endpoint at
05:27:48.780089Z/05:27:48.833946Z, without failure codes. Health warnings=[],
free_bytes14445342720; its services list is empty, so service acceptance uses the
independent Windows query and observer proof above. Inventory warnings=[] and
hardware UUID/hostname/IP match the original physical PC. Unchanged inventory
reuses snapshot54f8bf9d-2d7e-489e-8d8c-34a48d39609f with an older collected_at;
the fresh completed collection and last_observed_at establish re-observation,
not newly changed hardware content.

Chrome/Yandex remain CLOSED with policy APPLIED/native host READY, without an
extension heartbeat. Browser telemetry remains the user's known deferred issue;
no physical USB/print event or WorkTime employee flow is claimed. General fleet
remains disabled/revision1/max_parallel1, fleet decisions0. The original clean120
qualification872a53bc-17f3-48ac-a481-dfeaaac2f961 remains unchanged; this
administratively prepared result does not replace or widen it. No server deploy,
new artifact, primary-release promotion or general legacy156 ACL fix occurred.

Receipts: accepted-status.json, native-accepted-summary.json,
ssh158-postflight.json, companion-processes.json, private158-comparison.json and
post-collections-fleet.jsonl in the private operator directory below. Sensitive
before-file metadata and authentication inputs are not committed.

## Target acceptance requirements

Require applied bridge/return, actual full Setup exit0, exact native/Core158 and
source/MSI bindings, no pending transaction, private-four continuity, restored
ordinary companions, stable180-second observation, independent new target WSS,
fresh accepted user samples/activity and post-install Endpoint health/inventory.
No manual native retry or recovery-hold clearing is permitted.

For the initial server-only attempt none of the native158 gates passed. Read-only
SMB metadata and SCM configuration queries were used for diagnosis only. Before
the separately authorized administrative continuation above, no
workstation SSH, writes/staging, remote process execution, task, ACL/owner change,
service restart, observer installation or enrollment/identity replacement occurred.

Operator receipts and bounded maintenance helper:
`C:\Temp\endpoint-test29-20261105`.
