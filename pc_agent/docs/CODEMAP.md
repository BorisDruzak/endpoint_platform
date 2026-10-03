# Endpoint Agent code map

## Runtime boundary

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
verified staging and durable preparation. Setup alone lazily imports
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

Endpoint Policy delivery and ACK run in `policy/runtime.py` through the same
Gateway connection. The Windows local sensor boundary has a service-owned,
cancellable named-pipe listener in `platform/windows/sensor_pipe_listener.py`.
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

`platform/windows/print_sensor.py` subscribes to local spooler ADD_JOB changes
with only printer name, user name, total pages and total bytes requested. It
does not request the document-title field, read spool files or persist the
local job ID. Unsafe printer names become bounded hashes. The runtime starts
the worker before restoring cached policy and accepts `print_events=audit` only
while the notification worker and protected SecurityEvent spool are available.
Native subscription start/stop has passed on Windows; a real disposable print
job and durable server/Console projection are still acceptance gates.

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

## Excluded legacy surfaces

The Endpoint core intentionally contains no desktop GUI, requester/ticket
client, local Helpdesk account session, Helpdesk WebSocket agent, Protocol V3
database/outbox, or Remote Assist runtime activation. Packaging specs and
runtime verification enforce this boundary.
