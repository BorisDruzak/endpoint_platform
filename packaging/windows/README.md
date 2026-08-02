# Endpoint Agent Windows MSI

This directory builds one machine-wide x64 MSI for the headless Endpoint
Agent. It uses `pc_agent/pyinstaller_endpoint_core_windows.spec`; the legacy
Helpdesk/GUI agent specifications are not MSI inputs.

## Build

Prerequisites are Python with PyInstaller and the WiX Toolset 4 `wix` command
with `WixToolset.Util.wixext` available. From the repository root:

```powershell
.\packaging\windows\build-msi.ps1 -Configuration Release -Platform x64
```

The build directory contains the staged payload, generated WiX payload
binding, a SHA-256 file/service/component manifest, and—when WiX is
available—the MSI plus a direct MSI-table inspection manifest. The build has
no parameter for enrollment or device material and does not read such input.

The checked-in `initial-runtime.version` is the immutable first runtime. A
different initial runtime requires both `-InitialRuntimeVersion` and the
explicit `-ApproveInitialRuntimeTransition` switch. Routine major upgrades
upgrade MSI-owned launcher/service metadata while keeping ProgramData and the
existing `current.json` selection. `RemoveExistingProducts` runs inside the
MSI transaction; vital service installation and the updater ACL action fail
the transaction instead of continuing with a partial service installation.

## Installed security boundary

- `EndpointAgent` runs as `NT AUTHORITY\LocalService` and is automatic-start.
- `EndpointAgentUpdater` runs as `LocalSystem` and is demand-start only.
- Program Files inherits the standard administrator-only write policy; the
  installer adds no ordinary-user write ACL.
- `C:\ProgramData\Endpoint Platform\Agent` receives an explicit inheritable
  ACL for SYSTEM, Administrators, and the two service identities.
- The MSI contains only binaries, the immutable initial selector, this public
  documentation, and a public configuration template. Provisioning happens
  after installation through the separately reviewed protected handoff.

Default uninstall removes both services and the Program Files binary tree,
including updater-published version directories. It deliberately preserves
ProgramData so repair or reinstall retains machine identity and credentials.

## Explicit administrator purge

After uninstall, an administrator may deliberately erase retained local
state. Verify the literal path before running:

```powershell
$endpointAgentData = 'C:\ProgramData\Endpoint Platform\Agent'
if ([IO.Path]::GetFullPath($endpointAgentData) -eq 'C:\ProgramData\Endpoint Platform\Agent') {
    Remove-Item -LiteralPath $endpointAgentData -Recurse -Force
}
```

This purge is irreversible and removes enrollment identity, credentials,
update state, and logs. It is intentionally not part of default uninstall.
