# Endpoint Agent

`pc_agent` is a headless Endpoint Platform runtime. It enrolls a device,
maintains device credentials, executes approved Endpoint commands, and reports
typed Device Context collections through the Gateway transport.

## Canonical entrypoints

- Runtime: `pc_agent/runtime/main.py`
- Linux core build: `pc_agent/pyinstaller_endpoint_core_linux.spec`
- Windows core build: `pc_agent/pyinstaller_endpoint_core_windows.spec`
- Linux RPM packaging: `packaging/alt/build-rpm.sh`
- Windows MSI packaging: `packaging/windows/build-msi.ps1`

The runtime has no Helpdesk requester UI, local ticket API, WebSocket command
transport, Protocol V3 storage, or Remote Assist activation path. Remote
Assist source remains a separately managed module and is excluded from the
core artifacts.

See [CODEMAP.md](CODEMAP.md) for the active architecture,
[AUTHENTICATION.md](AUTHENTICATION.md) for device credentials, and
[AGENT_UPDATE_WORKFLOW.md](AGENT_UPDATE_WORKFLOW.md) for immutable releases.
