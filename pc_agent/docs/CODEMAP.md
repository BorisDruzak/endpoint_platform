# Endpoint Agent code map

## Runtime boundary

`power/native.py` defines metadata-only native pages and deterministic UUIDs from
source, actual OS boot identity and native record ID. `power/spool.py` owns a
separate protected `power-events-v1.db`: page insertion, loss counters and cursor
updates share one SQLite FULL-synchronous transaction. Its 30-day/10,000-event/
5-MiB payload limits do not change SecurityEvent retention. Exact ordered power
ACKs dispose accepted/rejected items; retry_later stays queued and permanent
rejections retain only bounded quarantine metadata.
Batch sizing shares `transport/base.py:gateway_wire_size` with the WSS sender:
the complete envelope uses aiohttp's default JSON wire spacing/UTF-8 bytes,
including worst-case sequence width, within the dedicated 60-KiB power limit.

`power/runtime.py` starts persistent collection/notification tasks before network
connection and sends through a per-connection sender only after negotiating
`endpoint.power-events.v1`. Source/queue failures update source availability and
retry locally; transport/authentication failures still reach the ordinary
lifecycle. A timed-out native read is retained so repeated polls do not multiply
blocked workers. `runtime/lifecycle.py` routes power ACKs independently of policy.

`platform/windows/power_events.py` recovers forward System provider/ID metadata,
uses Kernel-Boot27 BootType for full-boot versus Fast Startup/hibernate resume,
and registers PowrProf suspend/resume callbacks. Latest native boot identity is
separate from historical replay. One bounded reverse Boot27 lookup recovers
context before the first replay row even if its boot predates the30-day fact
window. The context shares the existing atomic page/checkpoint transaction.
Fixed subprocess reads (10-second deadline, kill-and-wait on cancellation) share
one loop-scoped lock with SCM evidence. The frozen core dispatches the private
stdin-only `--windows-power-read` mode; static imports keep the worker in the
existing build closure. Native reads use no default-executor threads.
`platform/linux/power_events.py` uses trusted
UID0/unit/PID1 metadata, forward journal cursors, kernel boot identity and public
logind signal subscriptions through `busctl wait`. No journal privilege helper
or main service privilege change is needed. Native log limitations remain
visible as availability/loss/reset diagnostics; see
`docs/architecture/agent-power-collection.md` for precise source mappings.

The fixed Windows `service_launcher.py` forwards SCM shutdown as `S` then EOF;
ordinary service stop remains EOF only. `runtime/main.py` persists the shutdown
fact within a two-second budget before stopping the child. Older cores already
stop on any byte/EOF, and update-pending runtime exit retains precedence.

Gateway WSS EOF/abnormal closure (including aiohttp CLOSED/CLOSING sentinels)
uses the existing retry lifecycle instead of ending the Windows service. A
sentinel retains the socket's real close code, so credential and policy
rejection remain fail-closed. Underlying TLS exceptions remain terminal;
certificate and hostname validation are unchanged.


`platform/windows/staged_update_state.py` separates an installer-owned
application journal from the native MSI fence. Its immutable binding includes
the genuine old/new package identities, original selector bytes and full core
tree identities. Ordinary OTA mutation fails closed while preparation or trial
is active, including after an abandoned owner mutex. Preparation itself creates
no native launch fence; later trial integration admits only the exact selected
candidate. Journal mutations require fresh installer checkpoint scope, strict
protected state ACLs and durable publication. The journal API alone neither
starts MSI nor establishes installed update/rollback acceptance.

`platform/windows/retained_storage.py` keeps the v1 capture receipt immutable
and records a separate v2 payload location. A staged native reconciliation
renames the verified archive payload into `versions` on one NTFS volume;
published runtime and archive validation read that single tree. Journal replay
finishes both directory barriers after a visible rename. Destination-parent
deletion authority is checked before movement, and known MSI residue is moved
aside without overwriting unrelated files. Only an actual rollback may recreate
the v1 duplicate layout required by an immutable predecessor helper. Ordinary
non-staged receipts keep their existing archive/rehydration behavior.

`installer_transaction_bridge.stage_online_update` captures retention and
enrollment descriptor evidence before SCM stops. The owner checks the original
Agent process before and after capture, then seals the exact selectors/media
after stopping services. A fresh native session adopts the original protected
capture through a separate operation-bound receipt; capability files and the
original capture binding remain immutable. Native prepare reuses the validated
capture. Numeric phase timing/grant counters contain no paths or identities.
The owner pipe drains ready frames and waits on pending I/O completion while
retaining its bounded owner-thread pump and per-mutation authentication.

`platform/windows/acl.py` validates enrollment leaf descriptors read-only during
installer data capture. Origin accepts the exact protected, explicit credential
policy written by `WindowsProvisioner`, plus the existing mutable installer and
provisioning policies. Other leaves retain their existing policies; validation
never repairs or propagates a DACL.

`msi_inventory.package_read_scope` reuses only verified immutable MSI inventory
and MSI file digests within one authenticated helper phase. Native file handles
deny write/delete;
every reuse checks namespace/file identity and returns an independent object.
Mutation checkpoints validate every pin after the live owner check. Only MSI
media under fixed package-digest execution directories and, outside native
callbacks, the native Windows Installer cache retain their deny-write/delete
handles across unrelated metadata writes. Outside native callbacks, the same
rule covers retained original MSI media in the exact package-digest archive
directories. Other handles and values are dropped.
Heavy authenticated phases may hash at most four explicit package-digest MSI
inputs with two read-only workers. The phase thread acquires every native pin
before dispatch; workers receive no owner grants or Native MSI authority.
Results become reusable only after all workers succeed and identities validate.
Native Installer cache paths are not prefetched.
Installed native state, ACL, Core payload, SCM and health remain fresh.
Complete MSI database semantics may be reused under the same native pins;
every registered-cache lookup, ACL, namespace, byte size and before/after
identity check still runs. Fresh post-commit `compound-finalize` may retain
byte proofs for the exact Foundation files from its authenticated
MSI. ACL, namespace and descriptor checks still run on every access. Native
deny-write/delete handles survive metadata-only checkpoints and are released
on context exit or failure. Other phases, recovery and the default Foundation
reader perform complete byte verification on every call. Reuse-budget
exhaustion falls back to the original fresh reader.

The fresh compound upgrade uses one `compound-finalize` helper only after real
native End(Commit)=0 and all required callbacks. It executes the same ordered
commit, retire, reconcile, finish and complete functions, including every native,
byte, ACL, owner-grant and durability check. Only the final ready marker may
acknowledge the outer phase. The active physical peer is journaled before the
first verification; partial failure retains the original recovery boundaries.
Recovery and repair retain their granular post-native helper sequence.

Windows specs use `tools/canary/tzdata_payload.py` to replace loose timezone
resources with one deterministic `tzdata-runtime.zip`. The pinned distribution's
package bytes, wheel hashes and license are preserved; package Python may contain
only version constants/empty initializers. `runtime_hook_tzdata_zip.py` validates
the bounded archive and resolves its standard zip importer without executing the
package before ordinary bootstrap checks. Invalid resources exit 63 without a
windowed exception dialog. Existing full payload hashes/native ownership cover
the archive file. Linux specs retain their existing resource layout.

`platform/windows/installer_launch_broker.py` initializes the new fixed helper
while the original Agent still runs. Its separate launch-only pipe authenticates
both peers through retained native identities and accepts only fixed owner-phase
and capability-session pairs from the same operation/owner/helper. Each phase
runs in a new same-executable PyInstaller worker; forced onefile-parent validation
is retained without forging bootloader environment variables.
Every extracted bootstrap resource is hardened to SYSTEM/Administrators and
pinned against writes/deletion/rename before reuse. Each launch revalidates the
whole extraction namespace, pinned identities and current DACLs. The owner checks
the child's PID, creation time, image/hash, SID/elevation and direct parent, then
uses the original HMAC conversation and mutation grants. The launcher grants no
MSI authority or completion. Its idle read also waits on the exact owner handle;
owner loss closes the connection and retires its retained child. Older helpers,
other operations and MSI custom actions keep their original cold launch path.

Staged recovery tasks use at most three one-minute failure restarts, with
`IgnoreNew` retaining a single active recovery. Their protected XML digest binds
the retry limits; historical tasks without a retry block remain readable. Each
attempt repeats physical-owner/native settlement and companion integrity checks.
Deferred or unknown companion-launch outcomes preserve the recovery task.

The owner dispatches Agent and Browser Policy starts
before waiting for both Running; native/trial admission and stable WSS/policy
checks remain mandatory. Browser Policy is stopped before Agent while its
applied registry policy persists; the late OTA gate still precedes Updater stop.
For a modern staged predecessor, exact old MSI/helper preparation also runs
online and retains native deny-write/delete handles through native admission.
The predecessor additionally performs its authenticated read-only inspection
online. That temporary bridge never becomes quiescent; all ordinary late
preparation and Native admission checks repeat after service quarantine.
The compound native pump waits on either channel's pending I/O event and the
pending native result, with a ten-millisecond bound. It issues no grants from
callbacks: both conversations, ownership checks and End* calls still execute
on the original owner thread. Waiting neither consumes packets nor closes the
async operations' event handles.
`installer_phase_diagnostics.profile_installer_phase` is disabled by default.
Only the exact SYSTEM/Administrators-protected installer-state flag
`diagnostic-phase-timing.enabled` containing `profile-v1\n` enables self timing
inside an already authenticated helper phase. Event 1002 contains bounded code
locations, call counts and timings; no arguments, values, locals or paths.
It attaches to no other process, grants no authority and cannot replace phase
errors. Diagnostic runs with it enabled are not performance acceptance.
`platform/windows/staged_trial_proof.py` uses a separate protected trial request
and Agent-writable proof. Native registration/shared bytes and the exact Core
inventory are checked before selecting the candidate. Runtime composition keeps
one writer across reconnects, observing actual successful WSS handshake,
heartbeat send and policy ACK send; disconnects invalidate the connection and a
new handshake clears prior observations. The owner also checks the running
candidate process, resets its monotonic 60-second window on nonce changes, and
enforces a 180-second total deadline. Acceptance is durably journaled before
cleanup can unblock OTA. Existing OTA startup proof remains separate. A missing
fresh policy ACK withholds acceptance; silence is never a no-assignment proof.

`platform/windows/staged_foundation_rollback.py` binds compensation to the
original unaccepted operation, preserved data capture and exact old/new media.
The owner uses fresh control/removal sessions and the immutable predecessor's
genuine helper ABI in one reverse native transaction. Old shared bytes, MSI
registration and complete original Core identities must agree before original
selectors return. The removal child's delayed commit callback has its own
protected receipt; its original native fence is archived without pretending a
normal whole-product uninstall completed. Unknown native settlement retains the
barrier. Genuine signed 3.2.79 uses an explicit extracted Foundation catalog and
its original callback-free ABI.

`platform/windows/staged_recovery.py` validates fixed cached Setup/MSI/owner
inputs, their hashes and the exact protected SYSTEM startup task before recovery.
A hidden cached Setup watchdog retains the original process handle; a fresh
owner must prove its death and establish a real empty MSI transaction barrier.
Original capabilities/data captures remain immutable, with a separate protected
fresh-owner receipt. Known interrupted forward work uses the existing genuine
compound/standalone recovery route before compensation. Authenticated native
recovery may restore a CreateFolder rollback's cleared root
AUTO_INHERITED bit from `installer_data_security.py`'s original capture. Root
identity, every other descriptor byte and every private leaf must still match.
An owner-bound empty MSI Begin/End barrier must complete before recovery prepare
is admitted. The root stays pinned against deletion; low-level SetFileSecurity restores the
captured bit without child ACL propagation. A live mutation grant and exact
post-write snapshot remain mandatory; the original capture is never rebased.
Only a confirmed new boot restarts a fresh trial; live owner loss requests rollback. Ambiguous reverse/native
settlement retains the barrier and reports recovery required. A recorded native
reboot result withholds trial while its protected volatile registry marker is
present. `staged_boot_marker.py` requires the intact, private persistent operation
witness; only a missing volatile leaf proves full shutdown. Recovery never
creates missing witnesses, and cleanup never deletes markers. WMI timestamps,
kernel GUIDs, delayed events and Fast Startup cannot substitute for this proof.
Every forward native attempt durably publishes an unresolved gate and fresh
marker before launch. An unresolved attempt requests compensation and blocks
trial; a successful outcome requires real native settlement and the exact new
release. 3010/1641 retain the marker captured before that native invocation.
A new boot resets the trial attempt. Terminal cleanup never reverses acceptance.
Companion capture records only already-running fixed roles; restoration requests
use the same still-active user SID/session and an interactive Scheduler token,
never Session 0. Service results and requested user launches are distinct.
Terminal journals and reused v2 storage positions are archived before the next
operation; immutable v1 capture receipts remain byte-identical.
After a completed companion-launch body, a failing post-use identity guard
permits one complete fresh native/shared-byte/pin verification. Entry failures
and launch failures propagate immediately; persistent post-use failure also
propagates. Launch requests are never replayed by this verification retry.

Foundation packaging uses six independent onedir/PYZ entrypoints with identical
DLL/data merged by `tools/canary/foundation_payload.py`. Offline updater and Tray
remain self-contained. `installer_host_entry.py` is the separate self-contained
MSI Binary entrypoint; `service_launcher.py` retains its installer CLI ABI.
`companion_processes.py` supplies fixed-path companion stopping without service
imports. `foundation_layout.py` defines shared File/Component bindings. MSI
inventory schema 2 authenticates every shared dependency and its Native keypath,
while schema 1 retains its exact eight executable contract. Full namespace,
directory/file ACL, hash and descriptor checks surround shared use; post-commit
pins grow only with that explicit bounded inventory. Installed performance and
matrix acceptance are recorded separately in the Task 8 report.

`tools/canary/ssl_payload.py` preserves an interpreter's required adjacent TLS
policy resource in every Windows analysis containing `ssl`. It binds the
unmodified stdlib source/resource bytes, rejects missing or ambiguous inputs,
and adds nothing to networkless graphs. Frozen Core version and actual TLS
context tests catch missing runtime data before Native admission.

The MSI build also runs `tools/canary/verify_msi_payload.py` against its actual
compiled package and release manifest before signing. This uses the same full
inventory/table reader as runtime admission. Empty shared metadata remains a
required regular file with exact zero size and empty SHA256; empty EXE/DLL/PYD
images and missing data remain invalid.

`endpoint_contracts` defers its model exports until requested. The pure
`runtime_payload` leaf therefore loads without initializing Pydantic or its
indirect network imports in the offline worker. The packaged updater's
`--verify-offline` mode exercises the installer-fence read under a temporary
fixture, as well as MSI-owned runtime validation, without reading product state.

The offline updater creates each new ZIP staging root atomically with the strict
protected payload DACL before extraction. Descendants inherit SYSTEM/Admin full
control and Users/Agent/Updater read/execute. A preserved legacy servicing parent
is not normalized; an existing staging name is refused without changing it.

Authenticated fresh standalone MSI preparation normalizes only fully admitted
native81 ZIP current/previous trees before native replacement. The existing MSI
payload DACL (SYSTEM/Administrators Full; Users and Agent/Updater service SIDs RX)
replaces historical servicing inheritance. Every object is pinned without delete
sharing and changed by its verified handle; payload bytes, identities, selectors
and complete native/cache proof are checked again. Interrupted preparation can
finish a mixed strict/legacy tree while original81 remains installed. Inspection,
costing, recovery and compound paths do not gain this mutation authority. Private
enrollment data and generic state ACL policy are unchanged.

The installer owner pump permits four hours for authenticated prepare, including
full retained-copy and repeated legacy-owner/ZIP closure. Reconcile retains two
hours; native MSI and other helpers retain thirty minutes. The deadline does not
renew on progress. All phases retain fresh mutation grants and immediate
owner-loss handling through the same live conversation.

Recovery-critical Windows update state uses `platform/windows/durable_state.py`:
pending handoffs, adapter journal arrays, selectors, startup attempt/proof,
terminal outcome and MSI selector rollback snapshots are file-flushed,
atomically replaced and directory-flushed before their consumer proceeds.
Lifecycle deletion also flushes metadata, including an already absent marker
on retry. ProgramData writers apply the fixed service DACL before temporary
payload bytes; privileged selector writers preserve the existing leaf owner
and DACL, using current.json as the policy for a new previous/snapshot leaf.
The offline updater imports this primitive and ACL boundary without importing
the online adapter/runtime. A confirmed candidate with failed cleanup remains
selected while cleanup is degraded; cleanup failure cannot manufacture a
terminal failure or replace the running candidate's selector. This API-level
durability does not establish acceptance under a genuine VM power reset.
Native directory API failures become chained `OSError` with their Windows
error code so portable recovery callers can handle them. The adapter reloads
and merges its scheduled journal after HTTP ACK; existing Linux leaf modes
are preserved and new journals use owner-only permissions.
Visible undelivered journal retries finish their directory flush before HTTP.
Verified reuse of a runtime directory also completes its versions-root flush
before selector/SCM consumers. A local startup-proof ACL failure withholds proof
while the authenticated control lifecycle continues.

`platform/windows/disk_readiness.py` bounds additional download, pinned-copy,
extraction and journal allocations with a 64-MiB or 10-percent margin, summed
per receiving volume. Existing retained cores already occupy space. Download
and extracted files are flushed before durable handoff. A disk-full rejection
keeps valid pending state for retry and reports bounded `disk_insufficient`.
The Windows recovery supervisor keeps the current core and WSS alive after
SCM starts the updater; the offline worker owns stopping the Agent only after
verified staging and durable preparation. The worker first reserves exact old
selector bytes in `current-restore.json` with the current selector's ACL and
persists an operation/candidate/attempt-bound `selector-transition.json`.
Shared `publish_prepared` restores this slot without a fresh payload allocation;
interrupted transitions reconcile before normal version eligibility. A proven
accepted journal precedes pending deletion and remains until cleanup finishes.
The online supervisor's bounded `recovery_pending` SCM starts are idempotent for
an active worker and reach a stopped worker without premature core shutdown;
HTTP terminal reporting waits for transition reconciliation. Setup alone lazily imports
`msi_disk_costing.py`, which uses restricted read-only Installer costing and
bounded inventory/path accounting for new MSI, cache, temp and old rollback
copies. This conservative budget does not claim completed native component
costing and unknown inventory blocks MSI before services are stopped.

The Windows device-binding dialog lives in `platform/windows/binding_dialog.py`
inside the existing tray executable. `platform/windows/device_binding.py`
validates ephemeral proofs and exchanges the fixed create action over the
existing protected named-pipe helpers. `runtime/application.py` owns the
connected service listener and `update_adapter.py` reuses the device-authenticated
HTTPS session. Tray never reads credentials or calls Endpoint. See
`docs/architecture/device-binding-first-wave.md` for scope, limits and acceptance.

`pc_agent/runtime/main.py` is the only supported runtime entrypoint. It builds
`RuntimeSettings`, starts `runtime/application.py`, and uses the authenticated
Endpoint Gateway WSS transport. The runtime owns enrollment identity, device
credentials, local SQLite state, Device Context collection, module lifecycle,
and update verification.

Windows Session Context invokes `quser` directly. The `query user` relay can
return a nonzero status despite valid session output; the direct command keeps
the existing zero-exit requirement, bounded capture, timeout and OEM decoding.
Runtime-only update ZIPs carry their own source/version and explicit minimum
launcher contract; the 3.2.121 session correction requires foundation 3.2.120.
This does not replace or relabel the separately signed 3.2.120 MSI foundation.

Endpoint Policy delivery and ACK run in `policy/runtime.py` through the same
Gateway connection. The Windows local sensor boundary has a service-owned,
cancellable named-pipe listener in `platform/windows/sensor_pipe_listener.py`.
`activity_ingress.py` and `local_sensor_protocol.py` own the shared content-free
sensor projection and local envelopes. `browser_bridge.py` owns the common
Chromium port framing, pinned origin/extension handshake and typed ACK stream;
`platform/{windows,linux}/browser_bridge.py` supplies only the authenticated
local pipe or Unix socket transport. The Linux bridge is not advertised until
its installed native-host and policy lifecycle have been accepted.
Linux `--linux-browser-bridge` dispatches before service configuration or
enrollment and runs as the caller's unprivileged UID. It reads only the public
`browser_sensor/extension-id.txt` shipped in the frozen artifact and binary
browser stdin; the existing system credential is never opened by that mode.
Windows compatibility imports retain the existing models; only the adapter
supplies the OS-authenticated session key.
`platform/linux/{identity,local_ipc,sensor_listener}.py` provides the Linux
boundary: UID/PID kernel credentials, logind graphical session, verified SSSD
UPN, mutually authenticated bounded Unix records and OS lock/inactive override.
The listener remains an optional adapter around the shared Activity projection.
`platform/linux/user_sensor{,_runtime}.py` parses bounded records from the
unprivileged native `platform/linux/kde_probe` helper and forwards only the
common local envelope. The optional ALT user-sensor RPM stages that helper,
its PID-only KWin script, a user unit and KDE autostart wrapper. Its private
environment file affects only that unit; System Core never imports Qt.
`platform/windows/activity_api.py` validates the pipe writer's OS identity and
projects typed user/browser observations; `activity_dispatch.py` holds a
bounded handoff for WSS reconnects. `RuntimeLifecycle` starts the listener on
Windows WSS before connecting and stops it on exit; the sender resumes on each
WSS connection only after the Agent has applied its policy and successfully
sent an `APPLIED` policy ACK. `ActivityDispatch` closes this gate on every
connection and before applying a replacement policy; an `ERROR` ACK or failed
ACK send leaves Activity queued. Health/status reporting keeps its independent
ACK gate so policy errors can still be reported. No Gateway frame or server
contract changes are required.

The negotiated `endpoint.telemetry-results.v1` channel is defined in
`endpoint_contracts/telemetry_results.py` and handled by `runtime/lifecycle.py`.
`runtime/application.py` advertises it on WSS and routes security dispositions
through `RuntimeDependencies.telemetry_result_handler` to
`SecurityEventRuntime.receive_result`. `transport/websocket.py` rejects
unnegotiated results and returns the transmitted sequence from
`send_security_event_batch`. The sender matches batch ID, sequence and ordered
pending subsets before deleting spool rows; permanent rejections persist in
`SecurityEventSpoolStats.rejected_permanent`. Legacy complete-batch ACK matching
is unchanged. See `docs/architecture/optional-telemetry-results.md` for provider-
first compatibility, transaction boundaries and local collector failure rules.

`security/spool.py` keeps typed SecurityEvents in a protected SQLite file under
the Agent data root. It discards the oldest event on the 1000-event or 5-MiB
serialized-payload bound, expires events after 24 hours, and persists separate
overflow and expiry counters. SQLite pages and rollback-journal overhead can
exceed the payload bound. `security/runtime.py` sends one WSS batch at a time,
replays it on timeout, and removes rows only after an exact persisted ACK. The
sender waits until `RuntimeLifecycle` has sent the policy ACK frame on the
current WSS connection before replaying any queued batch. The last registered
production Agent 3.2.67 does not advertise `endpoint.security-events.v1`; the
3.2.72 release candidate enables this path but still requires installed-agent proof.
The WSS transport also defines a negotiated `endpoint.browser-status.v1` frame
for bounded Chrome/Yandex observations. The 3.2.72 Windows release candidate
coalesces authenticated Native Bridge Hello/Heartbeat facts by browser and
applied policy, inspects App Paths, process metadata, owned policy values and
the installed Native Host manifest without writes, and sends one two-family
report per minute after the current WSS policy ACK. Missing App Paths or stale
registration is `UNKNOWN`, since it cannot prove browser absence. The server
stores per-family current facts and derives compliance from policy and report
freshness. Installed Bridge, extension heartbeat and package proof remain open.
For this feature version, the Agent core bundle includes the release-pinned
extension ID. The service pipe maps approved browser upload/paste metadata to
typed SecurityEvents and waits for a durable spool write before returning the
Native Messaging ACK. Duplicate IDs succeed only for identical queued payloads.
Server health/compliance projection and installed-Agent print proof remain open.

`platform/windows/usb_sensor.py` registers CfgMgr32 USB device-interface
arrival/removal notifications and hands bounded callbacks to a worker thread.
It projects only VID/PID, a hash of a stable instance serial when available,
and a USB removable flag; raw symbolic links remain local and are never
serialized into a SecurityEvent. The runtime starts the notification source
before restoring cached policy, and accepts `usb_device_events=audit` only
while that source is registered and the protected SecurityEvent spool exists.
Native callback delivery has been exercised synthetically on Windows; actual
plug/unplug, queue-loss health and server compliance remain open.

`platform/linux/usb_sensor.py` subscribes to kernel USB device events with
unprivileged netlink group 1. Both sender port and SCM credentials must identify
the kernel; bounded records exclude raw paths/serials, interfaces and synthetic
events. Boot ID plus kernel sequence gives stable event IDs. Windows and Linux
use `security/usb_projection.py` for the Policy gate and shared event DTOs.
Source failure withholds readiness; runtime composition and physical hotplug
acceptance remain pending.

`platform/windows/print_sensor.py` subscribes to local spooler ADD_JOB changes
with only printer name, user name, total pages and total bytes requested. It
does not request the document-title field, read spool files or persist the
local job ID. Unsafe printer names become bounded hashes. The runtime starts
the worker before restoring cached policy and accepts `print_events=audit` only
while the notification worker and protected SecurityEvent spool are available.
Native subscription start/stop has passed on Windows; a real disposable print
job and durable server/Console projection are still acceptance gates.

`security/print_projection.py` owns the Windows/Linux safe print DTO projection.
Linux `platform/linux/print_sensor.py` queries explicit CUPS IPP job metadata
over the local Unix socket. It pages job IDs past retained history, skips the
startup baseline and polls only newer IDs. CUPS job UUIDs give stable event
identifiers and creation timestamps; failed persistence retries the same frozen
metadata before advancing the cursor. Titles, spool files and raw printer URIs
never enter events; user identity and rounded byte counts remain unknown.
The native source and shared durable spool passed a disposable held-job probe;
installed WSS/Console print acceptance remains pending.

The interactive `user_sensor_runtime.py` samples each logon session and sends
bounded frames through the same authenticated pipe. MSI stages its fixed
`EndpointUserSensor.exe` and HKLM Run entry; signed release and live acceptance
remain open. Elevated Setup leaves it pending until a user logon. The fixed
`browser_bridge_entry.py` uses binary stdio and a packaged, pinned extension ID;
its console-mode `EndpointBrowserBridge.exe` and Chrome/Yandex machine-level
native-host registrations are MSI inputs. Live native-host handshake and browser
acceptance remain open.

`platform/windows/browser_policy.py` contains the fixed Chrome/Yandex
machine-policy value applicator and ownership-marker checks for the pinned
Browser Sensor extension. `browser_policy_helper.py` owns the typed named-pipe
contract and OS service-SID checks; `browser_policy_service_entry.py` runs the
MSI-owned LocalSystem service. The LocalService Agent calls it through
`policy/windows_sensors.py` and does not write HKLM itself. Installed-MSI,
effective-browser-policy and browser download/heartbeat proof remain open.

## Main packages

`browser_policy_protocol.py` is the closed, stdlib-only privileged helper
request/reply contract shared by Windows and Linux. Linux `seqpacket.py` owns
bounded per-record kernel credentials; `local_ipc.py` adds graphical-session
authorization. `platform/linux/browser_policy.py` owns one conservative
policy file per installed Chromium/Chrome/Yandex product and a root marker, preserves foreign GPO files, and uses
no-replace atomic publication. `browser_policy_helper.py` authenticates only
the dedicated Core UID before reading requests. Its fixed root service and
RPM/native-host wiring lives in the optional user-sensor package. Its isolated
Python root helper loads only the fixed stdlib package, while browser-bridge
selects the protected immutable Core in credential-free native-host mode.
Chromium and Chrome manifests pin the existing extension origin and are
config(noreplace). ALT Yandex 26.4 uses the verified root-owned binary at
`/usr/lib64/yandex/browser/yandex_browser`, its own managed policy directory at
`/etc/opt/yandex/browser/policies/managed`, and Chromium's system native-host
directory. Unrelated valid ExtensionInstallForcelist entries are preserved;
conflicting ExtensionSettings, blocklists and externally owned Endpoint entries
still fail closed. Relinquish is scoped to each browser family. `browser_status.py`
shares the existing Windows projection and ACK gating; Linux supplies only
read-only host facts. Policy and manifest presence never fabricate a heartbeat.
Linux Core >=3.2.123 wires the same SecurityEventRuntime/spool and Browser
Status runtime to Unix sensor IPC, kernel USB and local CUPS adapters. A failed
optional source does not prevent the other sources starting; requested audit
still requires actual source readiness. `_security_persistence_callback` owns
the common bounded thread-to-loop durable handoff. Gateway Browser/DLP receive
paths require both negotiated features and the Linux audit runtime version.
Private 3.2.123 ALT/KDE Wayland acceptance confirmed Chromium forced installation,
ADMIN heartbeat and upload/paste delivery in both management modes, plus CUPS
job delivery through the same WSS spool. Physical USB acceptance is postponed;
Chrome remains absent. The 2026-10-22 follow-up confirmed installed Yandex 26.4,
signed ADMIN installation and a real accepted Native Messaging Hello in Wayland.
ALT deterministic setup refusals use exit 78 through Core and launcher, matching
the systemd no-restart contract; they do not trigger version rollback. Transient
enrollment failures retain their existing retry status.

Linux diagnostics share `platform/linux/sessions.py` (bounded logind local
graphical sessions), `journal.py` (fixed severity/profile queries that exclude
message content), and `cups.py` (bounded metadata-only IPP through the local
CUPS Unix socket). `context_profiles/probe.py` uses logind and restricts manual
journal diagnostics to metadata. Existing eventlog and service/printer handlers
project these adapters into the same Windows/Linux DTOs. The RPM grants only
the supplementary journal-read group; code still runs as `endpoint-agent`.
CUPS-Get-Printers alone treats a well-formed no-queues response as an empty list;
Get-Jobs errors remain failures. Large cups-browsed discovery can saturate the
scheduler's default 100-client limit; that host capacity setting is separate
from the Agent's unchanged bounded request timeout and recovery supervision.
ALT software inventory scans up to 8192 records, fails on overflow, and no longer
silently discards installed packages after record 2048.

| Surface | Location | Responsibility |
| --- | --- | --- |
| Runtime | `pc_agent/runtime/` | headless lifecycle, local state, verification |
| Transport | `pc_agent/transport/` | Endpoint Gateway WSS protocol and HTTP compatibility |
| Policy | `pc_agent/policy/` | validated policy application and last-good cache |
| Security events | `pc_agent/security/` | protected bounded SQLite spool and ACK-gated WSS replay |
| USB/print audit | `pc_agent/platform/windows/{usb_sensor,print_sensor}.py` | local OS notifications projected to content-free SecurityEvents only under audit policy |
| Browser machine policy | `pc_agent/platform/windows/{browser_policy,browser_policy_helper,browser_policy_service_entry}.py`, `pc_agent/policy/windows_sensors.py` | fixed extension force-install values, authenticated helper IPC, ownership marker and safe relinquish |
| Local sensors | `pc_agent/platform/windows/{local_ipc,sensor_pipe_listener,activity_api,user_sensor,user_sensor_runtime,browser_bridge,browser_bridge_entry}.py` | bounded user/browser observation boundary; service listener, per-user sampler and binary native-host entrypoint |
| Enrollment | `pc_agent/enrollment_identity.py`, `pc_agent/device_credential.py` | device identity and credentials |
| Context | `pc_agent/context_profiles/` | typed context collection and execution |
| Modules | `pc_agent/modules/`, `pc_agent/module_manager.py` | managed module lifecycle |
| Updates | `pc_agent/gateway_update_runtime.py`, `pc_agent/update_adapter.py` | immutable update selection and application |
| Packaging | `packaging/alt/`, `packaging/windows/` | ALT RPM and Windows MSI artifacts |

`platform/windows/staged_candidate_payload.py` prepares incoming Core bytes
from Setup's internal archive against the authenticated MSI inventory. Its
operation-bound private storage journal supports an online same-volume
publication and before-switch cancellation without copying or selecting the payload. Native MSI
ownership, final installed checks and health/rollback gates remain authoritative.
Protected data and companion cancellation captures precede publication of the
`preparing` reservation, so owner loss at publication remains recoverable.
Before switching, `check_candidate_executable` runs only the fixed
`pc_agent.exe --print-version` CLI from the published candidate while the old
agent remains selected. It holds every candidate-file pin, verifies the full
payload before and after execution, and requires exact bounded output and a
live owner. Windows execution metadata binds the retained handle owner, group,
DACL and file attributes; loader-updated ChangeTime is not a content identity.
This offline executability check grants no Native or trial proof.

ALT native distribution assembly lives in `tools/build_alt_pilot_kit.py` and
`packaging/alt/pilot/`. It pins already qualified Core/User Sensor/runtime and
separate CUPS repair/rollback/source RPM bytes, adds a deterministic manifest,
and supplies a read-only integrity/clean-machine/RPM dependency gate. Revision 2
requires both native header and payload publisher signatures for all four custom
RPMs in an isolated trust database. Archive/manifest detached signing remains in
the external operator signer; only the pinned public key ships. Installation,
environment CA and unique one-use enrollment remain explicit native provisioning;
the public kit carries no device state or credential. No Gateway contract,
immutable runtime, automatic updater or server API is changed by this packaging.

## Excluded legacy surfaces

The Endpoint core intentionally contains no desktop GUI, requester/ticket
client, local Helpdesk account session, Helpdesk WebSocket agent, Protocol V3
database/outbox, or Remote Assist runtime activation. Packaging specs and
runtime verification enforce this boundary.

Final ALT recovery boundaries: USB keeps one pending kernel change and Print
keeps one bounded page; projection freezes each pending SecurityEvent until durable
handoff succeeds. CUPS acquires its no-history baseline in the supervised polling
loop. Common server Policy delivery retries SENSOR_NOT_READY after 30 seconds for
both platforms; Browser Status resumes after the current ACK even on ERROR, while
Activity still requires APPLIED. KDE autostart replaces its private environment
before restarting its own unit. See the current ALT baseline and parity ledger
for installed acceptance and remaining external gates.
