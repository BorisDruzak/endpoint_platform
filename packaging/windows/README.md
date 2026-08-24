# Endpoint Agent Windows MSI

This directory builds one machine-wide x64 MSI for the headless Endpoint
Agent. It uses the neutral core, non-GUI launcher, and fixed Windows service
host PyInstaller specifications; the legacy Helpdesk/GUI agent specifications
are not MSI inputs.

## Build

Prerequisites are Python with PyInstaller and the WiX Toolset 4 `wix` command
with `WixToolset.Util.wixext` available. The source tree must be Git-clean;
the builder refuses a dirty tree so its selector revision identifies the
packaged bytes. From the repository root:

```powershell
.\packaging\windows\build-msi.ps1 -Configuration Release -Platform x64 `
  -InitialRuntimeManifest .\packaging\windows\initial-runtime-3.2.17.json `
  -ApproveInitialRuntimeTransition -ApproveInitialRuntimeSourceChange
```

PyInstaller keeps its normal repository-local build output. WiX staging,
generated payload binding, MSI output, and MSI-table inspection instead use the
short, safe default `C:\endpoint-platform-wix-build\Release-x64` to avoid the
native cabinet tool's path-length limit. Pass `-WixBuildRoot <absolute-path>`
to choose another dedicated output directory; filesystem roots, reparse points,
and paths inside the repository are rejected. The build has no parameter for
enrollment or device material and does not read such input.

The checked-in `initial-runtime.json` remains the immutable `3.1.76` baseline.
The reviewed `initial-runtime-3.2.17.json` transition pins the Windows Device
Context and WSS update runtime with a new component GUID and must be built with both explicit
approval switches shown above. Each manifest pins its runtime version,
component GUID, canonical-LF source-file hashes, complete staged artifact tree identity,
and the CPython/PyInstaller producer identity, including
`PYTHONHASHSEED=0` so PyInstaller's `base_library.zip` entry order is stable.
Each completed build retains a versioned MSI in `<WixBuildRoot>\releases`; use
that copy for Windows Installer repair because later builds clean transient
staging and `output` files.
The manifest version must equal
`AGENT_VERSION`; every routine build hashes all staged runtime files before MSI
binding. A different reviewed manifest requires both
`-ApproveInitialRuntimeTransition` and
`-ApproveInitialRuntimeSourceChange`; the new manifest must use a new version
and component GUID. An approved transition atomically moves `current.json`
when it still selects the removed old initial runtime, while preserving another
selected runtime only after validating it. Routine major upgrades update
MSI-owned launcher/service metadata while keeping ProgramData and a valid
`current.json` selection.
`RemoveExistingProducts` runs inside the MSI transaction; vital service
installation and the ACL actions fail the transaction instead of continuing
with a partial service installation.

## Installed security boundary

- `EndpointAgent` runs as `NT AUTHORITY\LocalService` and is automatic-start.
- `EndpointAgentUpdater` runs as `LocalSystem` and is demand-start only.
- Both registrations enable unrestricted per-service SIDs. Their fixed
  `endpoint-agent-service.exe` SCM binary resolves the strict `current.json`
  selector on every agent-service start, so apply and rollback select the
  corresponding immutable runtime.
- Program Files inherits the standard administrator-only write policy; the
  installer adds no ordinary-user write ACL.
- A deferred non-impersonated action replaces the
  `C:\ProgramData\Endpoint Platform\Agent` DACL, disables inheritance, and
  grants only the reviewed rights to SYSTEM, Administrators, and the two
  service identities. Before that write it rejects every reparse path element
  and requires SYSTEM/Administrators ownership under the trusted ProgramData
  root.
- The MSI contains only binaries, the immutable initial selector, this public
  documentation, and a public configuration template. Provisioning happens
  after installation through the separately reviewed protected handoff.
- Each newly built MSI seals that initial selector as schema version 1 with the
  exact 40-character Git revision used for the build. Older installed
  version-only selectors remain launch-compatible for upgrade safety, but they
  do not provide the immutable provenance required by the Windows diagnostic
  canary; recover those hosts with a freshly built and installed MSI.

Default uninstall removes both services and the Program Files binary tree,
including updater-published version directories. It deliberately preserves
ProgramData so repair or reinstall retains machine identity and credentials.

## Update handoff

The running `EndpointAgent` is the only Windows update component with a network
client. It obtains a canary recommendation and artifact only from the
CA-verified Endpoint origin, validates the ZIP hash and size, then writes the
fixed protected `pending_update.json` path before exiting with code `42`.
`EndpointAgentUpdater` is `LocalSystem`, demand-start and offline: it consumes
only that fixed path, validates all paths/ACLs, updates the immutable selector,
and rolls it back after failed verification or absent startup proof. A release
is `applied` only after the new runtime completes Gateway WSS and reports that
post-restart proof to the controller.

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
