# Endpoint Agent Windows MSI

The current published release is **3.2.156**. Its exact packages, source revisions,
download links and qualification limits are recorded in
[`docs/releases/current-agent-release.json`](../../docs/releases/current-agent-release.json).
Use `initial-runtime-3.2.156.json` for this release; older immutable bindings below
remain historical build inputs. The Core update requires Foundation 3.2.156;
upgrade an older Foundation with the full signed Setup first.

This directory builds one machine-wide x64 MSI for the headless Endpoint
Agent. It uses the neutral core, non-GUI launcher, and fixed Windows service
host PyInstaller specifications; the legacy Helpdesk/GUI agent specifications
are not MSI inputs.

The MSI also stages the unprivileged User Sensor and the credential-free
`EndpointBrowserBridge.exe`. Machine-level Chrome and Chromium Native Messaging
registrations point to one MSI-owned manifest beside the executable; that
manifest allows only the pinned Endpoint Browser Sensor origin. The Chromium
registration follows the lookup string observed in the installed Yandex Browser
26.8.3.1002 binary. It does not set a global Native Messaging blocklist.
Installed-MSI registration and a real Yandex Browser handshake remain release
gates.

## Build

Prerequisites are Python with PyInstaller and the WiX Toolset 4 `wix` command
with `WixToolset.Util.wixext` available. The source tree must be Git-clean;
the builder refuses a dirty tree. A schema-5 manifest also requires independent
evidence for the retained initial-runtime stage. From the repository root:

```powershell
.\packaging\windows\build-msi.ps1 -Configuration Release -Platform x64 `
  -InitialRuntimeManifest .\packaging\windows\initial-runtime-3.2.74.json `
  -InitialRuntimeStageRoot <retained-runtime-stage-3.2.74> `
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
Context, universal enrollment setup, and WSS diagnostic-canary runtime.
`initial-runtime-3.2.74.json` pins the Browser Policy helper startup retry,
Browser Hello and interactive User Sensor restart fixes to the clean
`3a984720ac96be67b685679f6e7d151211f788b5` source and its separately
retained core stage. The 3.2.73 manifest remains historical evidence for the
installed Hello and companion-restart canary. The 3.2.72 manifest remains
historical evidence for the installed Browser Policy helper ACL canary. The
3.2.71 manifest remains historical
evidence for the first installed Policy and DLP canary. The 3.2.70 manifest remains historical
evidence for the retired candidate whose policy service failed to start during
the Windows canary. These transitions use distinct component GUIDs
and require the explicit approval switches shown above. Each manifest pins its runtime version,
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
then stages the same verified bytes and secret-free provenance in the
MSI-protected ProgramData evidence cache. It publishes provenance atomically
after checking the installed MSI product and starting `EndpointAgent`, while
preserving prior evidence if staging fails. It never accepts an arbitrary cache
location or enrollment material. Before invoking the MSI it stops only the
fixed `EndpointAgent` and `EndpointAgentUpdater` services and the system
Windows Installer service, starts
`EndpointAgent` before publishing provenance, and restores a previously running
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
distributing the MSI directly. It embeds the MSI, canonical MSI release
manifest, canary installation wrapper, endpoint CA, and a public HTTPS
configuration. The embedded manifest binds the MSI hash, product code,
version, and initial runtime identity. Setup uses the wrapper to create the
same protected MSI cache and installer provenance as a direct canary install.
When `-ExistingMsi` is used, `-ExistingMsiReleaseManifest` must name the
canonical `endpoint_windows_release_v1` MSI sidecar; a Setup sidecar cannot
supply the required MSI identity.
An enrolled-machine rerun compares the verified installed MSI provenance with
the bundled MSI release, independently of a selected ZIP runtime in
`current.json`. Missing or stale installer evidence causes the MSI path to run
again so the wrapper can restore it before Setup reports success.
Campaign choice, claims, and credentials are never
build inputs or command-line arguments:

```powershell
.\packaging\windows\build-setup.ps1 `
  -EndpointOrigin https://endpoint.sosnadmin.local `
  -EndpointCaFile 'C:\path\to\sosnadmin-local-ca.crt' `
  -InitialRuntimeManifest .\packaging\windows\initial-runtime-3.2.74.json `
  -InitialRuntimeStageRoot <retained-runtime-stage-3.2.74> `
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
the redacted installer flow to `C:\ProgramData\Endpoint Platform\Installer\install.log`.
Setup diagnostics stay outside the protected Agent data tree, including on an
interrupted fresh installation. This preserves the authenticated empty-root
recovery check. Older Setup versions can leave `Agent\install.log`; preserve
that evidence separately before operator-assisted recovery, without removing
enrollment data or clearing the installer transaction.
For example, a Windows Installer or provenance failure records
`status=INSTALL_FAILED`, `stage=MSI`, and the bounded `MSI_EVIDENCE_FAILED`
detail. During a major upgrade,
the new Setup stops the visible tray before invoking MSI; MSI intentionally
does not execute a legacy installed tray helper before replacing its files.
This keeps upgrades from older agents compatible while repair retains its
tray-stop safeguard.

## Fleet eligibility and installation for 3.2.82

Use the approved, signed and timestamped single-file Setup EXE for operator
installation and foundation upgrades. Run that same EXE elevated with
`--preflight` to emit one JSON record (`endpoint_windows_fleet_preflight_v1`,
at most 16 KiB) to inherited stdout. This branch runs before installer results,
logs, enrollment, service control, selector/provenance publication or repair.
The PyInstaller loader and restricted MSI costing engine may use temporary
scratch space; preflight does not change protected installed state or native
product/service registration. Actual signed redirected invocation and before /
after protected-state snapshots remain the post-freeze release gate.

Core and foundation are independent. Strict payload/receipt/native inventory
checks distinguish ZIP, live MSI ownership and protected retained MSI history.
A removed ProductCode cannot establish live ownership. Equal-version ZIP
handoff or an absent initial-runtime feature still needs Setup; a compatible
newer selected core is preserved. Current core with an older foundation is an
upgrade case. Any surviving installer fence, selector recovery or update
journal is active/degraded, including intentionally disabled services awaiting
installer reconciliation or reboot. Preflight never clears this evidence.

Eligibility precedence is UPDATE_IN_PROGRESS, PROVENANCE_CONFLICT,
FOUNDATION_UNKNOWN, DISK_INSUFFICIENT, SERVICE_INVALID,
CREDENTIAL_REPAIR_REQUIRED, TLS_REPAIR_REQUIRED, then ALREADY_CURRENT or
READY_FOR_SETUP_UPGRADE. Missing complete cost evidence yields DISK_UNKNOWN
for an otherwise-needed transition. Package-bound costing sums native MSI,
wrapper, incoming provenance and retained-copy allocations by receiving volume
before adding the existing margin. A target-version-only API call cannot infer
capacity from free bytes alone. ALREADY_CURRENT skips costs only when no
foundation, feature or ownership transition is required.

Credential presence/shape is not authentication; CA presence/parseability is
not a live strict TLS check. WSS status is historical local evidence with
current connectivity explicitly unknown. Commands stay on WSS and updates use
HTTPS; `migration_http_pull_fallback` remains false. Eligibility does not enable
a fleet minimum version and does not constitute installed or release approval.

For an explicitly requested report artifact, the canonical collector accepts
`-SetupPath <exact-approved-Setup-EXE> -TargetVersion 3.2.82`. It validates the
literal regular path, reparse ancestors, Authenticode Valid status and timestamp,
then invokes only `--preflight`; it never auto-selects a cached/newest EXE.
Add `-FleetEligibilityOnly` to write only fleet facts, including non-ready
states. `-OutputPath` must be a new artifact outside install/data/installer-state
roots. Without this switch, collection still performs the independent installed
service/ACL/local transport-evidence checks and the optional completion check.
Modern/retained ownership without canonical Setup input is refused; the old
collector path is limited to known immutable 79/81 package identities.

The operator is responsible for supplying the exact approved artifact; a valid
system-trusted signature is not an application-specific signer allowlist or a
substitute for matching retained release/source evidence. Installed verifier
READY means its collected local acceptance evidence passed, including the
protected historical transport record. Fresh provider presence, strict TLS/WSS
and a matching completion operation must be proven independently at release
acceptance. No manual ZIP installation or receipt editing is an 82 procedure.

## Update handoff

The running `EndpointAgent` is the only Windows update component with a network
client. It obtains a canary recommendation and artifact only from the
CA-verified Endpoint origin, validates the ZIP hash and size, and durably writes
the verified handoff to the fixed protected `pending_update.json` path. The
process-lifetime recovery supervisor then requests the demand-start updater
through SCM. The known-good Agent core remains alive until the offline updater
owns the stop, selector change, and restart transition.
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


## Staged Foundation updates

A newer Setup prepares retained Core trees while the old service runs, then
seals selectors and stops services for native replacement. Successful forward
reconciliation promotes retained payloads by same-volume NTFS rename. Only an
actual compensating rollback recreates the immutable predecessor's v1 layout.
Candidate acceptance requires a new WSS handshake, heartbeat, applied policy ACK
and a stable 60-second connection within a 180-second trial. A durable accepted
journal survives cleanup failure. Exit 67 means the candidate was rolled back;
Setup reports `ROLLED_BACK`, rather than `UPDATED`.

Within one authenticated helper phase, repeated reads of the exact same MSI
reuse its fully verified inventory while a native read handle denies writes and
deletion. Reuse checks the file/namespace identity and returns independent
manifest/component objects. Every mutation checkpoint first checks the live
owner, then drops these read handles and cached results. The next read and every
new phase perform full verification again. Native product/feature/component,
SCM, ACL, payload and health observations are never cached by this mechanism;
ordinary readers and POSIX validation keep their existing fresh-read behavior.
Optional reuse-budget exhaustion falls back to fresh full verification.

Online preparation also initializes a launch-only instance of the new fixed
helper before stopping the old Agent. It may launch only another copy of itself
for a fixed owner phase and a protected capability of the same owner/operation.
Each phase remains a separate process with fresh native identity and original
HMAC/mutation grants. Same-executable PyInstaller workers reuse the verified
parent's extraction; the forced parent check remains enabled. No private
bootloader environment is forged. Before reuse, the launcher hardens its own
private extraction to SYSTEM/Administrators and pins every file and directory
against writes, deletion and rename. Every child launch revalidates the complete
namespace, file identities and current security descriptors against those pins.
The launch pipe independently pins both
physical peers and conveys no native completion or mutation authority. The
owner verifies each new child's creation time, hash, SID and direct parent.
Older immutable helpers and MSI-launched custom actions retain their existing
path. Owner-loss recovery, native barriers and health acceptance are unchanged;
installed performance and fault acceptance still require real guest evidence.

Recovery tasks retry a failed attempt at most three times, one minute apart,
without overlapping instances. Every retry establishes fresh native settlement
and owner authorization. Deferred companion launch retains the authenticated
task; retry never converts missing evidence into terminal success. Historical
captured tasks without restart settings remain valid. All new restart settings
are included in the captured task XML digest.

Compensating candidate removal passes `ENDPOINT_STAGED_REMOVE=1` to preserve
the original retained and OTA Core trees from recursive root cleanup. The MSI
preflight accepts this flag only for its authenticated staged removal role;
ordinary uninstall retains its normal cleanup behavior. Native removal entry
validates the previously captured maintenance authority, since Windows Installer
may already have unpublished the candidate product by that deferred action.

Before preparation, Setup caches its signed image and exact MSI/manifest/owner
program under the fixed protected `installer-cache/msi-<package SHA256>` path.
One operation-bound SYSTEM startup task runs that cached Setup with
`--recover-staged-update <canonical UUID>` and starts a bounded live watchdog.
Recovery validates hashes, task definition/principal/DACL and actual old-owner
process identity, takes the product mutex and establishes native settlement.
It never reuses an old session's grants. Known forward interruptions use the
existing native recovery path before compensation; only a confirmed new boot
requests a fresh health attempt. Uncertain reverse settlement retains its evidence
for explicit recovery. A reboot-required native result cannot enter a health
trial before the OS boot identity changes. User companions are requested only
for previously observed roles in the same active SID/session; missing sessions
are reported separately. The startup task is removed only after terminal
journal evidence; cached inputs and prior operation receipts remain protected.

These source contracts are not a fleet-readiness or installed-acceptance claim.
Genuine predecessor upgrade/rollback and performance results belong in the
release's dedicated Windows acceptance report.

Setup also embeds `EndpointCore.zip`, generated from the exact authored MSI
Core. The owner caches and pins it at the package-hash path. The authenticated
online phase verifies its complete inventory, compatibility contract and every
member against the signed MSI inventory, then writes each member once into a
protected operation directory while the old Agent runs, then publishes it into
`Agent/versions` by same-volume NTFS rename. The existing staged launch gate
still allows only the exact old selected tree. Managed stop and sealing retain
their existing revalidation. Publication grants no ownership authority. Native MSI
still registers and verifies all original features/components and supplies its
ownership metadata. Matching-file retention must be measured on the real MSI;
the separate two-file native probe is not full-package acceptance.

The small candidate storage journal binds every rename to the immutable staged
operation. Recovery after an interrupted rename uses the existing exact tree;
before-switch cancellation moves a complete published tree back only after
native-settlement and original-state proof. Partial private staging remains
protected evidence. Foreign destination, unknown state, extra members, reparse
points and mismatched payloads fail closed. No selected Core is changed during
online preparation. Historical wrappers without the optional internal archive
retain their existing path. New Setup builds require the archive; reusing an
existing MSI requires its matching `InitialRuntimeStageRoot` if native staging
is unavailable. Setup budgets the archive cache in addition to native costing.

Owner timing diagnostics separate process launch from whole-phase duration and
record warm/cold selection in memory. One protected diagnostic document is
written after the operation; these measurements grant no installer authority.

Managed switching stops the independent Browser Policy service before Agent;
its applied policy values persist. The late OTA gate remains after Agent stop
and before Updater stop. Following authenticated finish/trial admission, both
Agent and Browser Policy starts are dispatched before waiting for either.
The two-channel native pump waits for pending pipe I/O or native completion
instead of polling with one-millisecond PowerShell sleeps. The wait is bounded
to ten milliseconds and grants no authority: physical ownership, authenticated
conversation steps, native results and settlement still run on the owner thread.
The asynchronous operations retain ownership of their wait handles.
Both must still reach Running, and acceptance retains its fresh WSS, matching
APPLIED policy, exact candidate and stable-health requirements. SCM startup
failures still enter the ordinary staged rollback path.

For a modern predecessor, the online owner also prepares its exact cached MSI
and embedded old helper before Agent stop. Native deny-write/delete handles
remain open until the operation finishes. The native driver still checks the
media bytes and the immutable old helpers repeat their normal admission after
stop. Canonical legacy and interrupted/recovery paths retain their existing
behavior. This moves existing preparation outside the Agent connectivity gap;
it removes no native, hash, identity or ACL verification.

The launcher, service, provisioner, UserSensor, BrowserBridge and BrowserPolicy
specs now produce independent onedir executables. The MSI build merges only
identical DLL/data into `_foundation-runtime`; differing collisions or aliases
fail before publication. Original PYZ code remains separate. Offline updater
and Tray remain onefile. A separate onefile `endpoint-installer-host.exe` is
embedded as the MSI Binary. Schema 2 records every shared file and its exact
Native File/Component binding; old schema 1 packages remain supported. This
packaging change requires fresh signed Native performance and rollback
acceptance; it does not itself establish the 120-second target.

Windows specs also collect the build interpreter's required adjacent public
TLS policy resource when its actual `ssl` module references that resource.
Missing, reparsed or hardlinked inputs fail the build. The stdlib TLS code
and policy bytes remain unchanged; certificate and hostname verification
remain enabled. Networkless updater graphs do not gain SSL or policy data.
Frozen Core execution and an actual TLS context are tested before release.

Before signing, the build verifies the compiled MSI through the full runtime
inventory reader, including every File/Component/Feature/keypath binding.
Zero-byte shared metadata files retain complete presence, ACL, hash and Native
ownership checks; zero-byte executable images remain rejected.
