# Agent ↔ Endpoint residual inventory

Snapshot: `codex/endpoint-cancel-cutover` after the legacy cutover cleanup.
“Included” means imported by the Linux RPM or Windows MSI Endpoint Core
release paths.

| Surface | Classification | Linux / Windows / RPM / MSI | Disposition |
| --- | --- | --- | --- |
| `pc_agent/runtime/**` | RELEASED_HEADLESS | yes / yes / yes / yes | canonical Endpoint runtime |
| `pc_agent/transport/**` | RELEASED_HEADLESS | yes / yes / yes / yes | TLS Gateway WSS with bounded transitional HTTP pull |
| `pc_agent/context_profiles/**` | RELEASED_HEADLESS | yes / yes / yes / yes | typed, read-only Device Context collection |
| `pc_agent/primitives/**` | RELEASED_HEADLESS | yes / yes / yes / yes | fixed network and read-only capabilities |
| `pc_agent/enrollment_identity.py`, `pc_agent/device_credential.py` | RELEASED_HEADLESS | yes / yes / yes / yes | Endpoint device identity and credentials |
| `pc_agent/modules_packages/**` | MANAGED_MODULE_SOURCE | no / no / no / no | retained package source; no core activation path |
| `pc_agent/remote_assist/**` | MANAGED_MODULE_SOURCE | no / no / no / no | retained source only; excluded from Core and not activated |
| `pc_agent/pyinstaller_endpoint_core_linux.spec` | RELEASED_HEADLESS | yes / n/a / yes / no | Linux Core artifact |
| `pc_agent/pyinstaller_endpoint_core_windows.spec` | RELEASED_HEADLESS | n/a / yes / no / yes | Windows Core artifact |
| `packaging/alt/build-rpm.sh` | RELEASED_HEADLESS | yes / no / yes / no | immutable ALT RPM input |
| `packaging/windows/build-msi.ps1` | RELEASED_HEADLESS | no / yes / no / yes | immutable Windows MSI input |

## Retired surfaces

The former desktop requester UI, local ticket client, account/session state,
Helpdesk WebSocket runtime, legacy local database/outbox/scheduler, historic
GUI release builders, and their dependent tests have been removed. They are
not a fallback, compatibility path, or package input.

## Capability boundary

Endpoint Agent exposes only typed Endpoint Gateway capabilities. Ticket
workflow, requester experience, consent interaction, and Remote Assist
activation remain outside the core runtime and require separately approved
contracts before they can be introduced.
