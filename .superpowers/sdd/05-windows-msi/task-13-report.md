# Task 13 — Machine-wide Windows MSI report

## Status

Implemented the machine-wide x64 Windows MSI source, headless Windows release
binding, deterministic payload/component manifest, service registration and
uninstall/upgrade policy in the designated isolated worktree.

No service was installed, started, stopped, or changed. No production or test
host was contacted. No release was uploaded and no canary was scheduled.

The headless PyInstaller staging build completed. The MSI itself could not be
bound or table-inspected because this workstation has neither the WiX `wix`
command nor a .NET SDK. The installed `dotnet.exe` is only a host and reports
`No .NET SDKs were found` for tool commands.

## Implementation

- Added WiX 4 package, directory, component, service, and upgrade sources under
  `packaging/windows/wix/` with stable UpgradeCode
  `D4F3045C-51CF-49D9-AF9C-3AEBF206ED1F`, per-machine scope and x64 component
  bitness.
- Added `packaging/windows/build-msi.ps1`. It builds only
  `pyinstaller_endpoint_core_windows.spec` plus the stable non-GUI launcher,
  stages the core as immutable `versions/3.1.76/pc_agent.exe`, generates stable
  component ids for every onedir dependency, writes a SHA-256 binding manifest,
  invokes WiX when available, and then queries MSI File, Component,
  ServiceInstall and Property tables through Windows Installer COM.
- Added an explicit checked-in `initial-runtime.version`. Changing it requires
  both `-InitialRuntimeVersion` and `-ApproveInitialRuntimeTransition`; the
  default major-upgrade path retains `current.json` with `NeverOverwrite` and
  uses in-transaction `afterInstallExecute` component reference counting.
- Registered `EndpointAgent` as automatic `NT AUTHORITY\LocalService` and
  `EndpointAgentUpdater` as demand-start `LocalSystem`. Both registrations are
  vital, uninstall-controlled, wait for stop, and have restart recovery.
- Added the fixed no-argument
  `--windows-restrict-updater-start` frozen-entrypoint mode. The deferred,
  non-impersonated, return-checked MSI action calls the already-reviewed Task 12
  service DACL function after `InstallServices` and hides its target.
- Added an explicit permanent ProgramData ACL for SYSTEM, Administrators,
  `NT SERVICE\EndpointAgent`, and `NT SERVICE\EndpointAgentUpdater`. No Users or
  Everyone ACE and no Program Files permission override is authored.
- Default uninstall removes the services and recursively removes the remembered
  Program Files tree, including updater-created version directories. The
  recursive removal is conditioned out of a major upgrade. ProgramData is a
  permanent component and is retained.
- Added a public config template and an explicit administrator-only ProgramData
  purge command. No enrollment, campaign, device bearer, or credential input is
  accepted or embedded by the build.
- Changed `pc_agent/build_windows_release_v2.py` from the inherited GUI agent and
  portable GUI-era launcher specs to the neutral headless core and stable
  non-GUI launcher. The onedir executable is renamed to the fixed Windows
  updater contract `pc_agent.exe` only in the versioned release layout.
- Updated `pc_agent/docs/AGENT_UPDATE_WORKFLOW.md` and
  `pc_agent/docs/CODEMAP.md` for the new artifact paths and MSI boundary.

## TDD evidence

### RED 1 — absent MSI contract and GUI-oriented canonical builder

Created `tests/packaging/test_windows_msi_contract.py`, then ran:

```powershell
python -m pytest tests\packaging\test_windows_msi_contract.py -q
```

Result: `15 failed`. Fourteen failures were the expected missing WiX/build files;
the release-builder assertion also showed the existing canonical script still
selected `pyinstaller_agent_win_release.spec`.

### RED 2 — fixed updater ACL custom-action entrypoint absent

```powershell
python -m pytest tests\packaging\test_windows_msi_contract.py::test_updater_acl_custom_action_reaches_only_the_fixed_no_argument_boundary -q
```

Result: expected `SystemExit: 2`; argparse did not recognize
`--windows-restrict-updater-start`.

### GREEN 1 — authored MSI and headless build contract

After the minimal WiX, builder, entrypoint, assets, and documentation changes:

```powershell
python -m pytest tests\packaging\test_windows_msi_contract.py -q
```

Result: `16 passed in 0.58s`.

### RED/GREEN 3 — Windows PowerShell 5.1 build compatibility

The first real staging build built both PyInstaller artifacts and then failed
because Windows PowerShell 5.1 has no `utf8NoBOM` encoding enum. A focused
regression assertion failed on that token before the builder moved to the
.NET UTF-8-no-BOM writer.

The next run exposed two other .NET Framework boundaries:
`Path.GetRelativePath` and static `SHA256.HashData`. The same focused contract
was extended and observed failing before implementing URI-based relative paths
and `SHA256.Create().ComputeHash()`.

Final focused result: `1 passed in 0.02s`.

## Build and inspection evidence

Prepare/stage command:

```powershell
.\packaging\windows\build-msi.ps1 -Configuration Release -Platform x64 -PrepareOnly
```

Both PyInstaller 6.19.0 builds completed. A subsequent reuse-stage completed
in 9.3 seconds and produced:

`packaging/windows/build/Release-x64/output/binding-manifest.json`

Manifest/generated-source inspection reported:

- 2,496 staged files;
- 2,498 components (one component per generated dependency plus authored
  service/state components);
- two services with the fixed accounts/start modes/recovery;
- all required anchors present: launcher, selector, config, documentation and
  versioned `pc_agent.exe`;
- generated WiX parsed as XML;
- no secret-named payload path;
- `scope=perMachine`, `architecture=x64`, permanent ProgramData, no ordinary
  Program Files user write grant, and `embedded_private_material=false`.

The staged core ran `--help` successfully and exposed the neutral runtime,
service/updater, fixed updater ACL, verify and safe-status modes. Direct archive
inspection confirmed these frozen modules are present:

- `pc_agent.runtime.application`
- `pc_agent.platform.windows.service`
- `pc_agent.platform.windows.service_control`
- `pc_agent.platform.windows.updater_service`

Exact required command:

```powershell
.\packaging\windows\build-msi.ps1 -Configuration Release -Platform x64
```

It rebuilt both binaries, regenerated the binding manifest, then exited `1`
with the exact intended external blocker:

`WiX Toolset 4 command 'wix' is unavailable. Install a .NET SDK and the WiX 4 global/local tool, then rerun this command.`

Therefore no MSI file exists and the post-bind MSI table inspection could not
run. The script is ready to perform that inspection automatically when WiX is
available.

## Final verification

```powershell
python -m ruff check pc_agent\build_windows_release_v2.py pc_agent\runtime\main.py tests\packaging\test_windows_msi_contract.py
```

Result: `All checks passed!`

```powershell
python -m pytest tests\packaging\test_windows_msi_contract.py pc_agent\tests\windows pc_agent\tests\runtime\test_dependency_split.py -q
```

Result: `97 passed in 47.52s`.

```powershell
python -m pytest tests\packaging pc_agent\tests\runtime -q
```

Result: `102 passed, 1 skipped in 48.67s`. The skip is the existing
non-applicable platform case.

`python -m compileall -q pc_agent/runtime pc_agent/build_windows_release_v2.py tests/packaging`
and `git diff --check` both exited `0`; Git printed only existing line-ending
conversion notices.

The repository-recommended `scripts/verify_workspace.py` and
`scripts/run_ci_suite.py` do not exist in this isolated endpoint worktree, so
they could not be run. The focused replacement suites above were run instead.

## Constraints and residual concerns

- WiX authoring and generated binding were validated structurally but were not
  compiled. A machine with a .NET SDK, WiX 4, and `WixToolset.Util.wixext` must
  run the exact build command before release.
- Because no MSI exists, ICE validation, direct MSI table comparison, install,
  repair, major-upgrade rollback, uninstall and explicit purge need a disposable
  Windows MSI pilot. No real service test was authorized or performed here.
- PyInstaller emitted the existing Python 3.14 warning that Pydantic V1
  compatibility is unavailable. The headless build and dependency-boundary
  tests still completed, but the production build image should use the project
  lock/toolchain chosen by release engineering.
- This task creates packaging/build behavior only. It does not bump or publish
  an agent version, upload an artifact, assign a rollout, or contact a host.

## Review fix round 1

The first review identified four release-blocking contracts. This round fixed
all four without installing an MSI or changing any service or host.

### Stable SCM path and selected-runtime supervision

SCM now binds both services to the fixed Program Files binary
`endpoint-agent-service.exe`. `EndpointAgent --agent-service` strictly reloads
`current.json` on every start, rejects unknown fields, non-triplet versions,
traversal, missing files, symlinks, and Windows reparse points, then supervises
the selected `versions/<version>/pc_agent.exe --windows-service-child` process.
Closing the child's private stdin control pipe forwards SCM stop/shutdown; a
pre-start stop is latched so it cannot race an orphaned spawn. Exit `42` starts
only the fixed demand-start updater. Thus candidate start, confirmation, and
rollback now execute the version named by the selector rather than the MSI's
initial runtime forever.

RED evidence was the missing `service_launcher` module, missing child mode, and
the later stop-before-spawn test launching a child after stop. The focused
GREEN suite includes literal old-to-new selector assertions and finished with
all service-launcher cases passing.

### Service SID and exact ProgramData DACL

Both `ServiceInstall` rows now author core WiX `ServiceConfig` with
`ServiceSid="unrestricted"` on install and reinstall. The former additive
`util:PermissionEx` entries were removed. A fixed, deferred,
non-impersonated, return-checked `--apply-programdata-acl` action runs after
`InstallServices`, replaces the DACL, and uses
`PROTECTED_DACL_SECURITY_INFORMATION` to disable inheritance. The executable
policy test verifies the exact inheritable ACE masks: SYSTEM/Admin full,
EndpointAgent read/write/delete, and EndpointAgentUpdater write/delete only.
The updater-start service DACL action now also runs through the fixed host.

RED evidence was the absent `replace_machine_data_acl` boundary and the
initial updater modify mask including read. Both focused tests failed on those
specific omissions before the protected exact policy passed.

### Immutable initial-runtime identity

`initial-runtime.version` was replaced by `initial-runtime.json`, which pins
version `3.1.76`, the versioned-core component GUID, and sorted SHA-256 hashes
for 50 reviewed core source inputs. The build validates it before PyInstaller. A
transition requires a separate manifest, both
`-ApproveInitialRuntimeTransition` and
`-ApproveInitialRuntimeSourceChange`, and a new version plus a new component
GUID. The manifest component GUID is passed into WiX, preventing a new
absolute version path from silently reusing the old component identity.

RED evidence covered a changed file behind the same label, one-approval
transitions, same-version/GUID transitions, and the real transition case where
old source bytes are no longer present. The validator now checks candidate
bytes while retaining the baseline manifest only as the identity comparison.

### Review-round build and verification evidence

The exact required command was rerun:

```powershell
.\packaging\windows\build-msi.ps1 -Configuration Release -Platform x64
```

It built the neutral core, non-GUI launcher, and new fixed service host, wrote
the binding manifest, and then exited only at the existing external gate:

`WiX Toolset 4 command 'wix' is unavailable.`

The regenerated manifest contains 2,497 files and 2,499 components. It records
`EndpointAgent` as fixed binary `ProgramFiles/endpoint-agent-service.exe`,
argument `--agent-service`, selector `ProgramFiles/current.json`, and the
updater as the same fixed binary with `--updater-service`. Both the fixed host
and `versions/3.1.76/pc_agent.exe` are present. Frozen `--help` smoke checks
confirmed the host's four fixed modes and the core's new
`--windows-service-child` mode.

Final verification:

```powershell
python -m pytest -q pc_agent/tests/windows tests/packaging/test_windows_msi_contract.py tests/packaging/test_initial_runtime_contract.py tests/build/test_linux_headless_artifact.py pc_agent/tests/runtime
```

Result: `176 passed, 5 skipped in 48.94s`; skips are platform-specific.

The checked-in manifest validator, Ruff, `compileall`, Windows PowerShell AST
parsing, and `git diff --check` all exited zero. WiX compilation/table
inspection and a disposable-machine MSI lifecycle pilot remain blocked only by
the unchanged absence of WiX/.NET SDK on this workstation.

## Review fix round 2

No deployment, service operation, host access, release upload, or rollout was
performed in this round.

### Cancellable child stop signal and exit 42

The previous `asyncio.to_thread(sys.stdin.buffer.read, 1)` watcher could be
cancelled as a Task but left its default-executor worker blocked. On runtime
exit `42`, `asyncio.run()` then waited in `shutdown_default_executor()` while
the fixed host still held stdin open, so the host never observed 42 and never
started the updater.

The regression uses a real held-open OS pipe and a runtime returning 42. RED
recorded the interpreter's fatal shutdown exit; cleanup closed the pipe only
after capturing that failure. The final watcher is a nonblocking poll rather
than either an executor task or a daemon reader, so `asyncio.run()` returns 42
while the pipe is still open. The focused service/selector suite is GREEN.

### Approved selector migration before service start

`NeverOverwrite` remains the correct routine-upgrade policy, but an approved
new initial version would otherwise install the new component, preserve an old
initial selector, and later remove that old component. The MSI now writes a
validated fixed HKLM contract containing approval, baseline version, and new
version. A deferred, non-impersonated, return-checked fixed-host action runs
after `InstallServices`, the ProgramData ACL action, and the updater service
DACL action, therefore before the standard `StartServices` action.

The migration validates the new executable first. If `current.json` still
selects the baseline initial version, it atomically replaces the selector. If
another version is selected, it preserves it only after validating a regular
non-reparse executable inside the fixed versions root; a dangling or unsafe
selector fails installation before service start. RED was the absent module
and MSI property/action. GREEN covers old-initial migration, valid alternate
preservation, dangling alternate rejection, fixed no-path entrypoint, registry
values, gating condition, and action ordering.

### Complete artifact and toolchain identity

Manifest schema 2 retains reviewed source hashes and additionally pins:

- `agent_version`, which must equal both manifest `version` and the literal
  `AGENT_VERSION` in `pc_agent/version.py`;
- the complete staged onedir tree file count and canonical SHA-256 root over
  every path, size, and file digest;
- CPython implementation/version/platform, PyInstaller version, and a fixed
  `SOURCE_DATE_EPOCH` producer identity.

The build validates source/version/toolchain before PyInstaller and validates
the entire staged runtime before copying the remaining payload or invoking
WiX. Mismatched staged DLL/bootloader bytes or toolchain fail routine builds.
A changed producer is accepted only through a separate manifest with both
approvals, a new runtime version, and a new component GUID.

RED was five schema/API failures, including staged DLL mutation, mismatched
`AGENT_VERSION`, and PyInstaller version drift. All five manifest behavior
tests are GREEN.

The first clean build intentionally used a stale artifact placeholder and
failed closed with `initial runtime staged payload mismatch`. The resulting
complete runtime identity was then reviewed and pinned:

- 2,492 staged runtime files;
- tree SHA-256
  `31dbc29a1dbc74ea5c534c57393555a83f33c76318d973fef3d952381218d6f1`;
- CPython 3.14.3 / win-amd64 / PyInstaller 6.19.0 /
  `SOURCE_DATE_EPOCH=1767225600`.

A reuse-stage rerun passed that exact artifact gate, produced a binding
manifest with 2,497 files and 2,500 components, then failed only at the
unchanged intended WiX gate. The manifest carries the same artifact/toolchain
identity and the new transition-state component.

### ACL target trust

Before creating or modifying the fixed ProgramData subtree, the ACL action now
walks every existing path element with `lstat`, rejects symlinks and Windows
reparse attributes, safely creates missing descendants only below the trusted
ProgramData root, and verifies SYSTEM (`S-1-5-18`) or Administrators
(`S-1-5-32-544`) ownership. It repeats reparse and owner validation immediately
before replacing the protected DACL.

RED showed both a user-controlled directory symlink and a user SID owner
reaching the privileged write. Both now fail before `SetNamedSecurityInfo`;
the exact protected-DACL success policy remains GREEN.

### Verification evidence

Focused Windows/MSI/manifest verification after integration:

```powershell
python -m pytest -q pc_agent/tests/windows tests/packaging/test_windows_msi_contract.py tests/packaging/test_initial_runtime_contract.py
```

Result: `108 passed in 1.72s`.

The staged fixed host exposes `--migrate-initial-selector`; the staged core
still exposes `--windows-service-child`. Ruff, `compileall`, PowerShell AST
parsing, and `git diff --check` exited zero. The final broad suite is recorded
below after the last documentation and manifest verification pass.

```powershell
python -m pytest -q pc_agent/tests/windows tests/packaging/test_windows_msi_contract.py tests/packaging/test_initial_runtime_contract.py tests/build/test_linux_headless_artifact.py pc_agent/tests/runtime
```

Result: `186 passed, 5 skipped in 48.16s`; skips are platform-specific. The
same command invocation first revalidated the checked manifest against all
2,492 staged runtime files and returned the routine, non-transition identity.

### Review round 3: held stdin, rollback pairing, and selector provenance

The prior daemon reader could remain blocked in Python's buffered stdin during
interpreter shutdown. A real subprocess with its host pipe deliberately held
open exposed the Windows fatal-shutdown exit status `3221225477`, rather than
the runtime's `EXIT_UPDATE_PENDING` (42). The child now polls the inherited
Windows pipe with `PeekNamedPipe` and only reads once data is known available;
the non-Windows test path uses zero-timeout `select`. No reader thread or
executor worker remains alive at interpreter shutdown. The real held-open-pipe
regression now observes exit 42.

Selector migration writes a durable, fsynced snapshot before atomically
replacing `current.json`. The deferred MSI action has a paired no-argument
rollback action before it and a commit finalizer after it, all non-impersonated
and return-checked. Rollback restores the prior selector with the same atomic
replace before MSI removes candidate components or starts services; commit only
removes the snapshot.

An MSI-owned runtime is identified by the installed, exact-shape
`.endpoint-msi-runtime.json` marker (version, schema, and canonical component
GUID), staged with the immutable initial runtime. An old MSI-owned selector is
therefore migrated, while an updater-owned independently selected version is
still preserved. The rebuilt staged tree contains 2,493 files with SHA-256 root
`5a523a5c5d4b76c8e000188387edbab7a26ea730b5560a2134d2173e24033fc0`.

Focused regressions and the full Windows/packaging contract suite passed
(`113 passed`). Ruff, compileall, PowerShell AST parsing, and `git diff --check`
passed. A clean PyInstaller restage and a reuse-stage MSI build both passed
manifest and binding generation; the latter stopped only at the deliberate,
environmental WiX 4 command availability gate.
