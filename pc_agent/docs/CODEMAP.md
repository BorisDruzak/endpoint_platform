# Endpoint Agent code map

## Runtime boundary

`pc_agent/runtime/main.py` is the only supported runtime entrypoint. It builds
`RuntimeSettings`, starts `runtime/application.py`, and uses the Endpoint
Gateway HTTP transport. The runtime owns enrollment identity, device
credentials, local SQLite state, Device Context collection, module lifecycle,
and update verification.

## Main packages

| Surface | Location | Responsibility |
| --- | --- | --- |
| Runtime | `pc_agent/runtime/` | headless lifecycle, local state, verification |
| Transport | `pc_agent/endpoint_gateway.py` | Endpoint Gateway pull/report protocol |
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
