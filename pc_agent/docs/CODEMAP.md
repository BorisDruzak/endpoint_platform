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
bounded handoff for WSS reconnects. The listener is not yet started by
`RuntimeLifecycle`, and the user sensor/bridge are not yet packaged.

## Main packages

| Surface | Location | Responsibility |
| --- | --- | --- |
| Runtime | `pc_agent/runtime/` | headless lifecycle, local state, verification |
| Transport | `pc_agent/transport/` | Endpoint Gateway WSS protocol and HTTP compatibility |
| Policy | `pc_agent/policy/` | validated policy application and last-good cache |
| Local sensors | `pc_agent/platform/windows/{local_ipc,sensor_pipe_listener,activity_api,user_sensor,browser_bridge}.py` | bounded user/browser observation boundary, not yet service-wired |
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
