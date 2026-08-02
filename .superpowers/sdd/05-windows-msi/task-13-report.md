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
