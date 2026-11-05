# A2-INFAN-N full156 to158 through Endpoint

Status: BLOCKED before Core bootstrap download. Only the exact bridge rollout is
paused; native Setup158 was not assigned or executed. Core/Foundation remain156.

The user authorized a full update only on192.168.101.29 and verification of its
result and telemetry, without workstation preparation. Known Yandex browser
telemetry was previously deferred by the user and is not claimed as passed.

## Exact source and authority

Device dd5ebcfc-2e47-4d2b-ab29-85c689028b24, hostname A2-INFAN-N, authenticated
source192.168.101.29. Original physical inventory UUID
D09CEC00-C07E-11EC-9CE2-9A47AAD22C00; this is a workplace PC, not a disposable VM
despite its Temporary installer150 enrollment label. Source Core/Foundation156,
fresh matching WSS and no conflicting Core/native operation. No Setup-client
presence existed before this assignment. No workstation SSH, SMB staging, remote
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

The existing source is healthy, but this is not an update acceptance. A newer Core
cannot repair this source through the same staging path before being downloaded.
The current installed observer-free Foundation has not demonstrated an independent
privileged Endpoint bootstrap repair channel. No one-time domain/SSH/ACL workaround
was authorized by this task. Do not generalize the clean156 canary to all historical
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
Current source remains connected and collecting telemetry; target158 is not accepted.

## Unfulfilled target acceptance

Require applied bridge/return, actual full Setup exit0, exact native/Core158 and
source/MSI bindings, no pending transaction, private-four continuity, restored
ordinary companions, stable180-second observation, independent new target WSS,
fresh accepted user samples/activity and post-install Endpoint health/inventory.
No manual native retry or recovery-hold clearing is permitted.

For this operation none of the native158 gates is claimed as passed. Read-only
SMB metadata and SCM configuration queries were used for diagnosis only. No
workstation SSH, writes/staging, remote process execution, task, ACL/owner change,
service restart, observer installation or enrollment/identity replacement occurred.

Operator receipts and bounded maintenance helper:
`C:\Temp\endpoint-test29-20261105`.
