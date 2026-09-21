# Endpoint Agent Windows MSI

This directory builds one machine-wide x64 MSI for the headless Endpoint
Agent. It uses the neutral core, non-GUI launcher, and fixed Windows service
host PyInstaller specifications; the legacy Helpdesk/GUI agent specifications
are not MSI inputs.

## Build

Prerequisites are Python with PyInstaller and the WiX Toolset 4 `wix` command
with `WixToolset.Util.wixext` available. The source tree must be Git-clean;
the builder refuses a dirty tree. A schema-5 manifest also requires independent
evidence for the retained initial-runtime stage. From the repository root:

```powershell
.\packaging\windows\build-msi.ps1 -Configuration Release -Platform x64 `
  -InitialRuntimeManifest .\packaging\windows\initial-runtime-3.2.62.json `
  -InitialRuntimeStageRoot <retained-runtime-stage> `
  -InitialRuntimeStageEvidence <stage-evidence.json> `
  -ApproveInitialRuntimeTransition -ApproveInitialRuntimeSourceChange
```

PyInstaller keeps its normal repository-local build output. WiX staging,
generated payload binding, MSI output, and MSI-table inspection instead use the
short, safe default `C:\endpoint-platform-wix-build\Release-x64` to avoid the
native cabinet tool's path-length limit. Pass `-WixBuildRoot <absolute-path>`
to choose another dedicated output directory; filesystem roots, reparse points,
and paths inside the repository are rejected. The build has no parameter for
enrollment or device material and does not read such input.

The checked-in `initial-runtime.json` remains the immutable historical baseline.
The reviewed `initial-runtime-3.2.62.json` transition pins the Windows Device
Context, universal enrollment setup, and WSS diagnostic-canary runtime with a new component GUID and must be built with both explicit
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

## Schema-5 runtime provenance

Before a schema-5 MSI build, create the retained headless runtime stage from a
clean checkout and write evidence beside (not inside) that stage:

```powershell
python .\packaging\windows\initial_runtime_contract.py `
  --repository-root . `
  --artifact-root <retained-runtime-stage> `
  --write-stage-evidence <stage-evidence.json>
```

The evidence is generated without reading the release manifest. It records the
clean staging checkout's Git HEAD and the complete stage-tree identity. The MSI
builder rehashes the retained stage, verifies that evidence, and requires its
source revision to equal the manifest's `source_revision`; it then verifies
every manifest source hash against Git blobs at that revision. The revision
must be an ancestor of the clean MSI build checkout, but may precede the MSI
build commit when later commits change only release metadata or tests. Thus the
schema-1 selector, binding, and release sidecar identify the runtime-stage
source, not an unrelated later MSI-wrapper commit.

## Staging diagnostic canary

Use `Install-EndpointAgentCanary.ps1` only from an elevated PowerShell session
with the versioned MSI and its adjacent `*.release.json` sidecar. The wrapper
verifies the exact release manifest and MSI hash, copies that verified MSI to
a protected Program Files execution cache before invoking Windows Installer,
then records the same verified bytes and secret-free provenance in the
MSI-protected ProgramData evidence cache. It never accepts an arbitrary cache
location or enrollment material. Before invoking the MSI it stops only the
fixed `EndpointAgent` and `EndpointAgentUpdater` services and the system
Windows Installer service, starts
`EndpointAgent` after recording provenance, and restores a previously running
core agent if installation fails.

After the agent has completed a strict Gateway WSS connection, collect a
redacted readiness projection with
`tools/canary/Collect-WindowsAgentPreflight.ps1` and validate it with
`tools/canary/verify_installed_windows_agent.py`. A readiness projection may
have no command completion. After the one diagnostic operation, rerun the
collector with `-RequireCompletion`, the exact command ID, and
`context.diagnostic.collect`; the validator then accepts only that successful
bounded completion marker. Both stages verify the selector, installed MSI
provenance, protected local artifacts, and strict WSS status without reading
or reporting credential contents. The protected status retains only the
configured hostname so the collector can reject a connection to another FQDN;
it never records a full endpoint URL or authentication material.

## Installed security boundary

- `EndpointAgent` runs as `NT AUTHORITY\LocalService` and is automatic-start.
- `EndpointAgentUpdater` runs as `LocalSystem` and is demand-start only.
- Both registrations enable unrestricted per-service SIDs. Their fixed
  `endpoint-agent-service.exe` SCM binary resolves the strict `current.json`
  selector on every agent-service start and retains the protected provisioned
  Endpoint origin, so apply and rollback select the
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
  exact 40-character Git revision that staged the selected runtime. Older installed
  version-only selectors remain launch-compatible for upgrade safety, but they
  do not provide the immutable provenance required by the Windows diagnostic
  canary; recover those hosts with a freshly built and installed MSI.

Default uninstall removes both services and the Program Files binary tree,
including updater-published version directories. It deliberately preserves
ProgramData so repair or reinstall retains machine identity and credentials.

## Universal Windows setup EXE

For a new Windows machine, build the public, single-file setup EXE rather than
distributing the MSI directly. It embeds only the MSI, endpoint CA, and a
public HTTPS configuration; campaign choice, claims, and credentials are never
build inputs or command-line arguments:

```powershell
.\packaging\windows\build-setup.ps1 `
  -EndpointOrigin https://endpoint.sosnadmin.local `
  -EndpointCaFile 'C:\path\to\sosnadmin-local-ca.crt' `
  -InitialRuntimeManifest .\packaging\windows\initial-runtime-3.2.62.json `
  -InitialRuntimeStageRoot <retained-runtime-stage> `
  -InitialRuntimeStageEvidence <stage-evidence.json> `
  -ApproveInitialRuntimeTransition -ApproveInitialRuntimeSourceChange
```

The output is `EndpointAgentSetup-<version>-x64.exe` under the selected build
root's `releases` directory, with an adjacent `*.release.json` sidecar. The
sidecar binds the Setup and embedded MSI SHA-256 values, source revision, Agent
version, and Authenticode state. Supply an approved CurrentUser code-signing
certificate thumbprint and optional HTTPS timestamp only at build time; neither
certificate material nor enrollment authority is retained in the artifact.
Without that input the sidecar reports `unsigned`, which is suitable only for a
disposable test machine. Run the EXE elevated; `--quiet` suppresses UI but has
the identical enrollment flow. It returns `0` only after server completion,
`10` for an existing valid installation, and stable non-zero values for each
documented denial, claim, provisioning, service, or repair outcome.

On success or failure, Setup writes the machine-readable, non-secret result to
`C:\ProgramData\Endpoint Platform\Installer\install-result.json` and appends
the redacted installer flow to `C:\ProgramData\Endpoint Platform\Agent\install.log`.
For example, a Windows Installer failure records `status=INSTALL_FAILED`,
`stage=MSI`, and a bounded `MSI_EXIT_<code>` detail. During a major upgrade,
the new Setup stops the visible tray before invoking MSI; MSI intentionally
does not execute a legacy installed tray helper before replacing its files.
This keeps upgrades from older agents compatible while repair retains its
tray-stop safeguard.

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
