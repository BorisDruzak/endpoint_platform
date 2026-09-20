# Windows Agent Tray 3.2.51 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Endpoint Agent `3.2.51` with a safe per-user Windows tray companion that displays service, Endpoint connection, and update state, then upgrade and validate all three existing Windows test targets.

**Architecture:** The service and updater publish an atomically replaced, fixed-schema public status file under ProgramData. A separate, unprivileged `EndpointAgentTray.exe` consumes only that file and Windows Shell APIs; it has no credential, enrollment, configuration, transport, or service-control capability. WiX owns the binary and a per-user-logon launch entry while the headless service remains unchanged in session 0.

**Tech Stack:** Python 3.14, standard-library `ctypes` Win32 Shell bindings, PyInstaller, WiX Toolset 4, pytest, PowerShell, Authenticode.

**Spec:** `docs/superpowers/specs/2026-09-21-windows-agent-tray-3.2.51-design.md`

## Global Constraints

- Release version is exactly `3.2.51`; `3.2.50` must never be overwritten with a different payload.
- The tray is user-session-only and never runs from the service's session 0.
- Tray status is a fixed, atomically written and machine-owned public projection; it contains no credentials, identities, claims, command payloads, endpoint URLs, or mutable policy.
- The tray never opens HTTP/WSS connections and cannot enroll, update, restart, or configure the agent.
- Keep the release surface independent of all Helpdesk GUI/bridge modules and add no external Python dependency.
- Preserve strict TLS/WSS behavior and existing update/enrollment flows.
- Stop rollout immediately if any of the local, `192.168.101.2`, or `192.168.101.120` validations fails; never silently skip a target.

## Review Focus

- A user who can read ProgramData must not be able to replace a status file and make the tray report a forged healthy state; test ACL restoration and malformed/reparse rejection.
- An agent with no credential, invalid runtime configuration, or a transport exception must yield neutral/yellow or red status instead of a stale green icon.
- A malformed, future, or stale observation timestamp must never appear as a current Endpoint connection; test exact freshness bounds.
- A logged-in non-admin user must be able to run the tray while being unable to write the projection or stop the service; verify WiX registry and file ownership intent.
- A pending or failed update must take precedence over a healthy connection in icon selection, without exposing artifact paths or server reason text.

---

### Task 1: Public tray-status contract and protected writer

**Files:**
- Create: `pc_agent/platform/windows/tray_status.py`
- Create: `pc_agent/tests/windows/test_tray_status.py`
- Modify: `pc_agent/platform/windows/acl.py`

**Interfaces:**
- Consumes: fixed `data_root: Path`, `AGENT_VERSION: str`, runtime and update events.
- Produces: `TrayStatusWriter(data_root, version)`, `read_tray_status(data_root, now) -> TrayStatus`, and `TrayStatusError`.
- `TrayStatus` is a frozen dataclass with `version: str`, `agent_state: Literal["running", "starting", "stopped", "error"]`, `endpoint_state: Literal["connected", "connecting", "disconnected", "unknown"]`, `update_state: Literal["up_to_date", "pending", "applying", "failed", "unknown"]`, `observed_at: datetime`, and `reason_code: str | None`.

- [ ] **Step 1: Write failing contract tests**

```python
def test_writer_publishes_only_the_fixed_redacted_schema(tmp_path: Path) -> None:
    writer = TrayStatusWriter(tmp_path, "3.2.51", protect=lambda _path: None)
    writer.publish(agent_state="running", endpoint_state="connected", update_state="up_to_date")
    payload = json.loads((tmp_path / "tray" / "agent-status.json").read_text())
    assert set(payload) == {"schema_version", "version", "agent_state", "endpoint_state", "update_state", "observed_at", "reason_code"}
    assert "credential" not in json.dumps(payload)

def test_reader_rejects_stale_malformed_and_reparse_status(tmp_path: Path) -> None:
    tray_root = tmp_path / "tray"
    tray_root.mkdir()
    (tray_root / "agent-status.json").write_text("{}", encoding="utf-8")
    with pytest.raises(TrayStatusError):
        read_tray_status(tmp_path, now=known_now)
```

- [ ] **Step 2: Run the contract tests and verify RED**

Run: `python -m pytest pc_agent/tests/windows/test_tray_status.py -q`

Expected: FAIL because `tray_status` does not exist.

- [ ] **Step 3: Implement the strict status model and atomic publication**

```python
TRAY_STATUS_SCHEMA = "endpoint_windows_tray_status_v1"
TRAY_STATUS_FILENAME = "agent-status.json"
MAX_STATUS_AGE_SECONDS = 120

class TrayStatusWriter:
    def publish(self, *, agent_state: AgentState, endpoint_state: EndpointState,
                update_state: UpdateState, reason_code: str | None = None) -> None:
        # validate enum values and bounded reason code; write a 0600 temporary
        # file under data_root/tray; os.replace it; restore the exact public-read
        # DACL through the ACL adapter.
```

Add `protect_tray_status_file(path: Path)` to the ACL adapter. It must grant
read-and-execute only to `BUILTIN\\Users` while retaining service/system write
ownership; reject reparse points before every write/read boundary.

- [ ] **Step 4: Run the tray-status suite and targeted ACL tests**

Run: `python -m pytest pc_agent/tests/windows/test_tray_status.py pc_agent/tests/windows/test_acl.py -q`

Expected: PASS, including atomic replacement, forbidden fields, stale status,
malformed JSON, and reparse-point tests.

- [ ] **Step 5: Commit the public status contract**

```bash
git add pc_agent/platform/windows/tray_status.py pc_agent/platform/windows/acl.py pc_agent/tests/windows/test_tray_status.py
git commit -m "feat(windows): publish safe tray status"
```

### Task 2: Publish runtime and update transitions

**Files:**
- Modify: `pc_agent/runtime/lifecycle.py`
- Modify: `pc_agent/runtime/application.py`
- Modify: `pc_agent/platform/windows/updater_service.py`
- Modify: `pc_agent/tests/runtime/test_headless_lifecycle.py`
- Modify: `pc_agent/tests/windows/test_updater_service.py`
- Modify: `pc_agent/tests/windows/test_windows_online_update_runtime.py`

**Interfaces:**
- Consumes: `TrayStatusWriter` from Task 1.
- Produces: `TrayStatusWriter.publish(agent_state, endpoint_state, update_state, reason_code)` calls for startup, transport connect/reconnect, pending/applying/failed update outcomes, and terminal agent errors.

- [ ] **Step 1: Write failing lifecycle/update tests**

```python
async def test_lifecycle_projects_connected_and_retrying_states() -> None:
    events: list[tuple[str, str, str]] = []
    dependencies = RuntimeDependencies(
        load_credential=lambda _settings: "credential",
        create_executor=lambda: executor,
        create_transport=lambda _settings, _credential, _executor: transport,
        create_tray_status_writer=lambda _settings: Recorder(events),
    )
    assert await RuntimeLifecycle(settings, dependencies, RuntimeStatus()).run() == 0
    assert ("running", "connected", "up_to_date") in events
    assert ("running", "disconnected", "up_to_date") in events

def test_updater_projects_applying_then_failed_without_artifact_detail(tmp_path: Path) -> None:
    assert writer.events == [("running", "connected", "applying"), ("error", "unknown", "failed")]
```

- [ ] **Step 2: Run the selected tests and verify RED**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/windows/test_updater_service.py pc_agent/tests/windows/test_windows_online_update_runtime.py -q`

Expected: FAIL because `RuntimeDependencies` has no tray-status factory and the
updater does not publish tray update states.

- [ ] **Step 3: Integrate only bounded state transitions**

```python
class TrayStatusWriter(Protocol):
    def publish(self, *, agent_state: str, endpoint_state: str,
                update_state: str, reason_code: str | None = None) -> None:
        raise NotImplementedError

# RuntimeLifecycle: starting/connecting before connect; running/connected after
# verified WSS handshake; running/disconnected before retry; error/unknown on a
# terminal failure; pending before EXIT_UPDATE_PENDING.
```

Create the writer only on Windows in `application.py`. Keep a local last-known
update state in the writer; do not inspect protected pending artifacts from the
tray. In `updater_service.py`, publish `applying`, then either `up_to_date` on
confirmed startup or `failed` with a stable code such as `UPDATE_VALIDATION`,
`UPDATE_START`, or `UPDATE_ROLLBACK`. All writer failures must be logged and
must not replace the existing update safety decision.

- [ ] **Step 4: Run the selected suites and verify GREEN**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/windows/test_updater_service.py pc_agent/tests/windows/test_windows_online_update_runtime.py -q`

Expected: PASS with existing WSS/update behavior retained.

- [ ] **Step 5: Commit runtime projection integration**

```bash
git add pc_agent/runtime/lifecycle.py pc_agent/runtime/application.py pc_agent/platform/windows/updater_service.py pc_agent/tests/runtime/test_headless_lifecycle.py pc_agent/tests/windows/test_updater_service.py pc_agent/tests/windows/test_windows_online_update_runtime.py
git commit -m "feat(windows): project runtime status for tray"
```

### Task 3: Unprivileged native Windows tray companion

**Files:**
- Create: `pc_agent/platform/windows/tray.py`
- Create: `pc_agent/pyinstaller_windows_tray.spec`
- Create: `pc_agent/tests/windows/test_tray.py`
- Modify: `tests/architecture/test_no_helpdesk_agent_release_dependencies.py`

**Interfaces:**
- Consumes: `read_tray_status(data_root, now) -> TrayStatus` from Task 1.
- Produces: `status_to_view(status: TrayStatus | None, now: datetime) -> TrayView` and `run_tray(data_root: Path) -> int`.
- `TrayView` is a frozen dataclass with `icon: Literal["green", "yellow", "blue", "red", "grey"]`, `tooltip: str`, and exactly three menu label strings.

- [ ] **Step 1: Write failing view-model and isolation tests**

```python
def test_update_failure_precedes_connected_icon() -> None:
    tray_status = TrayStatus(
        version="3.2.51", agent_state="running", endpoint_state="connected",
        update_state="failed", observed_at=known_now, reason_code="UPDATE_VALIDATION",
    )
    view = status_to_view(tray_status, known_now)
    assert view.icon == "red"
    assert view.tooltip == "Endpoint Agent: error; Endpoint: connected; Update: failed"

def test_tray_module_has_no_transport_or_service_control_imports() -> None:
    source = Path("pc_agent/platform/windows/tray.py").read_text(encoding="utf-8")
    assert "aiohttp" not in source and "win32service" not in source
```

- [ ] **Step 2: Run tray tests and verify RED**

Run: `python -m pytest pc_agent/tests/windows/test_tray.py -q`

Expected: FAIL because the tray module and executable spec do not exist.

- [ ] **Step 3: Implement the tray in the standard library only**

```python
def status_to_view(status: TrayStatus | None, now: datetime) -> TrayView:
    # red errors first, then blue pending/applying, green only fresh WSS-ready,
    # yellow running-but-not-connected, grey absent/invalid/stale projection.

def run_tray(data_root: Path) -> int:
    # create a hidden message window with ctypes; register Shell_NotifyIcon;
    # use a timer to reload the fixed file; expose Details, Refresh, and Exit.
```

Use only `ctypes`, `datetime`, and the Task 1 reader. Encode disabled menu
labels as `Endpoint Agent: ` plus the agent-state value, `Endpoint: ` plus the
endpoint-state value, and `Update: ` plus the update-state value. `Details`
displays only the same `TrayView` data and
observation time. `Exit tray icon` destroys the notification icon and process;
there is no Windows service-control API call. Build it windowed (`console=False`)
as `EndpointAgentTray.exe` in a dedicated PyInstaller spec. Add the tray spec
to the released-path architecture test and explicitly forbid Helpdesk/UI bridge
imports.

- [ ] **Step 4: Run tray and architecture tests**

Run: `python -m pytest pc_agent/tests/windows/test_tray.py tests/architecture/test_no_helpdesk_agent_release_dependencies.py -q`

Expected: PASS, including icon precedence, stale/unknown presentation, menu
labels, no transport imports, and release-surface guards.

- [ ] **Step 5: Commit the tray companion**

```bash
git add pc_agent/platform/windows/tray.py pc_agent/pyinstaller_windows_tray.spec pc_agent/tests/windows/test_tray.py tests/architecture/test_no_helpdesk_agent_release_dependencies.py
git commit -m "feat(windows): add unprivileged tray companion"
```

### Task 4: MSI ownership and user-logon launch

**Files:**
- Modify: `packaging/windows/build-msi.ps1`
- Modify: `packaging/windows/wix/Services.wxs`
- Modify: `tests/packaging/test_windows_msi_contract.py`
- Modify: `tests/packaging/test_initial_runtime_contract.py`

**Interfaces:**
- Consumes: `EndpointAgentTray.exe` produced by Task 3.
- Produces: MSI file component `cmpTrayCompanion` and machine-wide `EndpointAgentTray` logon registration.

- [ ] **Step 1: Write failing MSI contract tests**

```python
def test_msi_owns_windowed_tray_binary_and_per_user_logon_entry() -> None:
    services = Path("packaging/windows/wix/Services.wxs").read_text(encoding="utf-8")
    assert 'Name="EndpointAgentTray.exe"' in services
    assert 'Key="Software\\Microsoft\\Windows\\CurrentVersion\\Run"' in services
    assert 'Name="EndpointAgentTray"' in services

def test_build_script_builds_the_tray_spec_before_wix_staging() -> None:
    assert "pyinstaller_windows_tray.spec" in Path("packaging/windows/build-msi.ps1").read_text()
```

- [ ] **Step 2: Run MSI contract tests and verify RED**

Run: `python -m pytest tests/packaging/test_windows_msi_contract.py tests/packaging/test_initial_runtime_contract.py -q`

Expected: FAIL because the tray binary is absent from MSI staging and no logon
entry is registered.

- [ ] **Step 3: Stage and own the tray binary**

```xml
<Component Id="cmpTrayCompanion" Directory="INSTALLFOLDER" Guid="*" Bitness="always64">
  <File Id="filEndpointAgentTray" Source="$(var.StagingDir)\ProgramFiles\EndpointAgentTray.exe" KeyPath="yes" />
  <RegistryValue Root="HKLM" Key="Software\Microsoft\Windows\CurrentVersion\Run"
                 Name="EndpointAgentTray" Value="&quot;[#filEndpointAgentTray]&quot;" Type="string" KeyPath="no" />
</Component>
```

Modify `build-msi.ps1` to build and stage `EndpointAgentTray.exe` alongside the
existing service artifacts, including its runtime files if PyInstaller emits a
one-directory bundle. Add only MSI-owned files; do not write an installer custom
action that launches UI from session 0. Ensure uninstall removes the registry
value and companion with the component.

- [ ] **Step 4: Run packaging contracts**

Run: `python -m pytest tests/packaging/test_windows_msi_contract.py -q`

Expected: PASS; source contracts require tray ownership and exclude
credential/enrollment-bearing properties. The versioned initial-runtime build is
performed only in Task 5 after its manifest exists.

- [ ] **Step 5: Commit MSI integration**

```bash
git add packaging/windows/build-msi.ps1 packaging/windows/wix/Services.wxs tests/packaging/test_windows_msi_contract.py tests/packaging/test_initial_runtime_contract.py
git commit -m "build(windows): package tray companion"
```

### Task 5: Versioned release, three-host upgrade, and evidence

**Files:**
- Modify: `pc_agent/version.py`
- Create: `packaging/windows/initial-runtime-3.2.51.json`
- Modify: `packaging/windows/README.md`
- Modify: `docs/superpowers/specs/2026-09-21-windows-agent-tray-3.2.51-design.md`

**Interfaces:**
- Consumes: signed release scripts, `3.2.51` source manifest, and the MSI tray component from Task 4.
- Produces: signed `EndpointAgentSetup-3.2.51-x64.exe`, signed MSI, release sidecars, and verified three-host rollout evidence.

- [ ] **Step 1: Write failing version/provenance checks**

```python
def test_current_product_has_approved_3_2_51_initial_runtime_transition() -> None:
    assert AGENT_VERSION == "3.2.51"
    assert Path("packaging/windows/initial-runtime-3.2.51.json").is_file()
```

- [ ] **Step 2: Run the selected check and verify RED**

Run: `python -m pytest tests/packaging/test_initial_runtime_contract.py -q`

Expected: FAIL because the version and approved source manifest are still
`3.2.50`.

- [ ] **Step 3: Build approved `3.2.51` runtime and signed installer artifacts**

Update `AGENT_VERSION`, create the schema-5 initial-runtime manifest with a new
component GUID, canonical source hashes, source revision, and independently
captured stage evidence. Run the existing runtime contract validator with both
approval switches. Build the MSI and Setup from a clean commit using the
corporate Authenticode certificate; verify the sidecar hashes and signatures
before transfer.

- [ ] **Step 4: Upgrade and validate every target in order**

For local workstation, `192.168.101.2`, and `192.168.101.120`:

```powershell
Start-Process -FilePath .\EndpointAgentSetup-3.2.51-x64.exe -ArgumentList '--quiet' -Wait -PassThru
Get-Content "$env:ProgramFiles\Endpoint Platform\Agent\current.json" -Raw
Get-Service EndpointAgent,EndpointAgentUpdater
Get-Content "$env:ProgramData\Endpoint Platform\Tray\agent-status.json" -Raw
Get-Process EndpointAgentTray -ErrorAction SilentlyContinue
```

Require setup exit `0`, selector version `3.2.51`, `EndpointAgent` Running/Auto,
`EndpointAgentUpdater` Stopped/Manual, valid safe tray status, and a tray process
in each active interactive validation session. Record only version, status, hash,
and process/service evidence; never record credentials or identity contents.

- [ ] **Step 5: Run full source verification and commit release documentation**

Run: `python -m pytest -q`

Expected: PASS. Update `packaging/windows/README.md` with tray behavior and the
`3.2.51` build command, update the design document with observed non-sensitive
canary results, then commit:

```bash
git add pc_agent/version.py packaging/windows/initial-runtime-3.2.51.json packaging/windows/README.md docs/superpowers/specs/2026-09-21-windows-agent-tray-3.2.51-design.md
git commit -m "build(windows): release tray companion 3.2.51"
```

## Self-review

- Intent/scope, no-privilege tray, public status projection, state mapping,
  context-menu behavior, MSI lifecycle, and all three rollout targets map to
  Tasks 1 through 5.
- No external dependency is introduced; Task 3 uses `ctypes` and is guarded
  against imports of transport/service/Helpdesk modules.
- Task 1 produces the exact `TrayStatusWriter` consumed by Task 2 and the
  reader consumed by Task 3; Task 4 consumes the Task 3 executable; Task 5
  consumes all prior release artifacts.
- Review-focus failure modes are covered respectively by Task 1, Task 2, Task
  1, Task 4, and Task 3 tests.
