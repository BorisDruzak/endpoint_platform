# Endpoint Agent code map

## Runtime boundary

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
WSS connection.

`security/spool.py` keeps typed SecurityEvents in a protected SQLite file under
the Agent data root. It discards the oldest event on the 1000-event or 5-MiB
serialized-payload bound, expires events after 24 hours, and persists separate
overflow and expiry counters. SQLite pages and rollback-journal overhead can
exceed the payload bound. `security/runtime.py` sends one WSS batch at a time,
replays it on timeout, and removes rows only after an exact persisted ACK. The
sender waits until `RuntimeLifecycle` has sent the policy ACK frame on the
current WSS connection before replaying any queued batch. The current 3.2.67
Agent does not advertise `endpoint.security-events.v1`; this
path activates at 3.2.70 after sensor integration and installed-agent proof.
For the future feature version, the Agent core bundle includes the release-pinned
extension ID. The service pipe maps approved browser upload/paste metadata to
typed SecurityEvents and waits for a durable spool write before returning the
Native Messaging ACK. Duplicate IDs succeed only for identical queued payloads.
USB/print producers and server health/compliance projection remain open.

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
