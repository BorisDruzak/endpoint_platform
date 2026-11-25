from __future__ import annotations

import asyncio
import json
import os
import runpy
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from pc_agent.version import EXIT_UPDATE_PENDING
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


@pytest.fixture
def modeled_runtime_ownership(monkeypatch):
    # Argument/selector tests use dummy executables; dedicated boot ownership
    # regressions below exercise real inventory and receipt verification.
    from pc_agent.platform.windows import service_launcher
    monkeypatch.setattr(service_launcher, '_verify_selected_runtime', lambda *_: None)


def _paths(tmp_path: Path) -> WindowsUpdatePaths:
    install = tmp_path / "install"
    data = tmp_path / "data"
    (install / "versions" / "3.1.76").mkdir(parents=True)
    (install / "versions" / "3.1.77").mkdir(parents=True)
    (install / "versions" / "3.1.76" / "pc_agent.exe").write_bytes(b"old")
    (install / "versions" / "3.1.77" / "pc_agent.exe").write_bytes(b"new")
    data.mkdir()
    return WindowsUpdatePaths(install, data / "updates" / "pending_update.json")


def test_retained_runtime_requires_full_archive_verification_before_launch(tmp_path,monkeypatch):
    from pc_agent.platform.windows import runtime_identity
    paths=_paths(tmp_path)
    (paths.versions_root/'3.1.76'/'.endpoint-retained-msi.json').write_text('{}')
    checked=[]
    def reject(paths,version):
        checked.append(version)
        raise ValueError('PROVENANCE_CONFLICT')
    monkeypatch.setattr(runtime_identity,'verify_retained_runtime',reject)
    with pytest.raises(ValueError,match='PROVENANCE_CONFLICT'):
        runtime_identity.validate_runtime_executable(paths,'3.1.76')
    assert checked==['3.1.76']


@pytest.mark.usefixtures("modeled_runtime_ownership")
def test_service_host_resolves_current_selector_on_each_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pinning SCM to the initial core would make an applied update ineffective."""
    from pc_agent.platform.windows import service_launcher

    build_agent_child_command = service_launcher.build_agent_child_command

    paths = _paths(tmp_path)
    monkeypatch.setattr(service_launcher, "AGENT_VERSION", "3.2.82", raising=False)
    monkeypatch.setenv("ENDPOINT_AGENT_LAUNCHER_VERSION", "99.0.0")
    paths.current_path.write_text('{"version":"3.1.76"}', encoding="utf-8")
    old = build_agent_child_command(paths)

    paths.current_path.write_text('{"version":"3.1.77"}', encoding="utf-8")
    new = build_agent_child_command(paths)

    assert old[0] == str(paths.versions_root / "3.1.76" / "pc_agent.exe")
    assert new[0] == str(paths.versions_root / "3.1.77" / "pc_agent.exe")
    assert old[1:] == new[1:]
    assert old[1:] == [
        "--windows-service-child",
        "--data-dir", str(paths.pending_path.parents[1]),
        "--install-root", str(paths.install_root),
        "--ca-file", str(paths.pending_path.parents[1] / "endpoint-ca.crt"),
        "--endpoint-origin", "https://endpoint.sosnadmin.local",
        "--transport-mode", "gateway_wss",
        "--no-migration-http-pull-fallback",
    ]


@pytest.mark.parametrize("foundation_version", ["3.2.81", "3.2.82"])
@pytest.mark.usefixtures("modeled_runtime_ownership")
def test_service_host_rolls_back_to_actual_frozen_core81_parser(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, foundation_version: str
) -> None:
    """A newer fixed host must start the unmodified 3.2.81 CLI on rollback."""
    from pc_agent.platform.windows import service_launcher
    from pc_agent.tests.windows.fixtures.core_3_2_81_parser import _parser

    paths = _paths(tmp_path)
    core = paths.versions_root / "3.2.81" / "pc_agent.exe"
    core.parent.mkdir()
    core.write_bytes(b"test-only selected runtime path; never executed")
    paths.current_path.write_text('{"version":"3.2.81"}', encoding="utf-8")
    monkeypatch.setattr(service_launcher, "AGENT_VERSION", foundation_version)
    monkeypatch.setenv("ENDPOINT_AGENT_LAUNCHER_VERSION", "99.0.0")

    command = service_launcher.build_agent_child_command(paths)
    arguments = _parser().parse_args(command[1:])

    assert command[0] == str(core)
    assert arguments.windows_service_child
    assert arguments.transport_mode == "gateway_wss"
    assert arguments.migration_http_pull_fallback is False
    assert "--launcher-version" not in command


@pytest.mark.parametrize("version", ["3.2.82", "3.2.83", "3.10.0", "4.0.0"])
@pytest.mark.usefixtures("modeled_runtime_ownership")
def test_service_host_passes_compiled_foundation_to_protocol82_cores(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, version: str
) -> None:
    """Protocol-aware selected cores receive the host version, never their own."""
    from pc_agent.platform.windows import service_launcher
    from pc_agent.runtime.main import _parser

    paths = _paths(tmp_path)
    core = paths.versions_root / version / "pc_agent.exe"
    core.parent.mkdir()
    core.write_bytes(b"test-only selected runtime path; never executed")
    paths.current_path.write_text(json.dumps({"version": version}), encoding="utf-8")
    monkeypatch.setattr(service_launcher, "AGENT_VERSION", "3.2.82")
    monkeypatch.setenv("ENDPOINT_AGENT_LAUNCHER_VERSION", "99.0.0")

    command = service_launcher.build_agent_child_command(paths)
    arguments = _parser().parse_args(command[1:])

    assert arguments.launcher_version == "3.2.82"
    assert arguments.windows_service_child
    assert arguments.transport_mode == "gateway_wss"
    assert arguments.migration_http_pull_fallback is False


@pytest.mark.usefixtures("modeled_runtime_ownership")
def test_service_host_uses_provisioned_endpoint_origin(tmp_path: Path) -> None:
    """A staging enrollment must not be redirected to the production endpoint."""
    from pc_agent.platform.windows.service_launcher import build_agent_child_command

    paths = _paths(tmp_path)
    paths.current_path.write_text('{"version":"3.1.77"}', encoding="utf-8")
    (paths.pending_path.parents[1] / "endpoint-origin").write_text(
        "https://endpoint-staging.sosnadmin.local", encoding="utf-8"
    )

    command = build_agent_child_command(paths)

    assert command[command.index("--endpoint-origin") + 1] == (
        "https://endpoint-staging.sosnadmin.local"
    )


@pytest.mark.usefixtures("modeled_runtime_ownership")
def test_service_host_accepts_revision_bound_current_selector(tmp_path: Path) -> None:
    """A freshly installed immutable MSI selector binds a runtime to its source SHA."""
    from pc_agent.platform.windows.service_launcher import build_agent_child_command

    paths = _paths(tmp_path)
    paths.current_path.write_text(json.dumps({
        "schema_version": 1,
        "source_revision": "a" * 40,
        "version": "3.1.77",
    }), encoding="utf-8")

    command = build_agent_child_command(paths)

    assert command[0] == str(paths.versions_root / "3.1.77" / "pc_agent.exe")


@pytest.mark.parametrize(
    "payload",
    [
        {"version": "../3.1.77"},
        {"version": "3.1.77", "extra": True},
        {"version": "3.1.77-beta"},
    ],
)
def test_service_host_rejects_noncanonical_current_selector(
    tmp_path: Path, payload: object
) -> None:
    """Selector ambiguity must not redirect LocalService outside a reviewed runtime."""
    from pc_agent.platform.windows.service_launcher import build_agent_child_command

    paths = _paths(tmp_path)
    paths.current_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="current selector"):
        build_agent_child_command(paths)


def test_service_child_stops_when_host_closes_control_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCM stop must reach the selected version without letting it host SCM itself."""
    from pc_agent.runtime import main as runtime_main

    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def run_until_cancelled(_settings) -> int:
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async def closed_pipe() -> bytes:
        await started.wait()
        return b""

    monkeypatch.setattr(runtime_main, "run_runtime", run_until_cancelled)
    monkeypatch.setattr(runtime_main, "_wait_for_service_host_pipe", closed_pipe)

    assert runtime_main.main([
        "--windows-service-child",
        "--launcher-version", "3.2.82",
        "--data-dir", "data",
        "--install-root", "install",
        "--ca-file", "ca.crt",
    ]) == 0
    assert cancelled.is_set()


@pytest.mark.usefixtures("modeled_runtime_ownership")
def test_service_host_latches_stop_before_selected_child_is_spawned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An SCM stop racing service startup must not launch an orphaned child."""
    from pc_agent.platform.windows import service_launcher

    paths = _paths(tmp_path)
    paths.current_path.write_text('{"version":"3.1.76"}', encoding="utf-8")
    spawned: list[object] = []
    monkeypatch.setattr(
        service_launcher.subprocess,
        "Popen",
        lambda *args, **kwargs: spawned.append((args, kwargs)),
    )
    coordinator = service_launcher.ChildProcessCoordinator(paths)

    coordinator.stop()

    assert coordinator.run() == 0
    assert spawned == []


def test_service_host_rejects_reparse_current_selector(tmp_path: Path) -> None:
    """An administrator-created selector link must not escape the fixed install root."""
    from pc_agent.platform.windows.service_launcher import build_agent_child_command

    paths = _paths(tmp_path)
    outside = tmp_path / "outside-current.json"
    outside.write_text('{"version":"3.1.77"}', encoding="utf-8")
    try:
        paths.current_path.symlink_to(outside)
    except OSError as error:
        pytest.skip(f"symlinks unavailable on this Windows test host: {error}")

    with pytest.raises(ValueError, match="reparse point"):
        build_agent_child_command(paths)


def test_service_child_propagates_exit_42_while_host_pipe_remains_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A cancelled blocking reader must not trap asyncio.run in executor shutdown."""
    from pc_agent.runtime import main as runtime_main

    async def update_pending(_settings) -> int:
        return EXIT_UPDATE_PENDING

    read_fd, write_fd = os.pipe()
    held_open_stdin = os.fdopen(read_fd, "r", encoding="utf-8")
    monkeypatch.setattr(runtime_main, "run_runtime", update_pending)
    monkeypatch.setattr(sys, "stdin", held_open_stdin)
    result: list[int] = []
    worker = threading.Thread(
        target=lambda: result.append(runtime_main.main([
            "--windows-service-child",
            "--launcher-version", "3.2.82",
            "--data-dir", str(tmp_path / "data"),
            "--install-root", str(tmp_path / "install"),
            "--ca-file", str(tmp_path / "ca.crt"),
        ]))
    )
    worker.start()
    finished_while_pipe_open = False
    try:
        worker.join(timeout=0.5)
        finished_while_pipe_open = not worker.is_alive()
    finally:
        os.close(write_fd)
        worker.join(timeout=2)
        held_open_stdin.close()

    assert finished_while_pipe_open
    assert result == [EXIT_UPDATE_PENDING]


def test_service_child_subprocess_exits_42_with_held_open_host_pipe() -> None:
    """A real child process must not abort Python shutdown with its host pipe open."""
    project_root = Path(__file__).resolve().parents[3]
    code = """
import asyncio
from pc_agent.runtime import main
async def update_pending(_settings):
    return 42
main.run_runtime = update_pending
raise SystemExit(main.main([
    '--windows-service-child', '--data-dir', 'data', '--install-root', 'install',
    '--ca-file', 'ca.crt', '--launcher-version', '3.2.82',
]))
"""
    environment = {**os.environ, "PYTHONPATH": str(project_root)}
    child = subprocess.Popen(
        [sys.executable, "-c", code],
        cwd=project_root,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        exit_code = child.wait(timeout=4)
    except subprocess.TimeoutExpired:
        child.terminate()
        child.wait(timeout=2)
        pytest.fail("service child did not exit while the host pipe stayed open")
    finally:
        if child.stdin is not None:
            child.stdin.close()

    assert exit_code == EXIT_UPDATE_PENDING


def _transition_contract(path: Path, *, previous: str, new: str) -> Path:
    contract = path / "initial-runtime-transition.json"
    contract.write_text(json.dumps({
        "approved": True,
        "from_version": previous,
        "schema_version": 1,
        "source_revision": "a" * 40,
        "to_version": new,
    }), encoding="utf-8")
    return contract


def _provenance_transition_contract(path: Path, *, previous: str, new: str) -> Path:
    contract = path / "initial-runtime-transition-provenance.json"
    contract.write_text(json.dumps({
        "approved": True,
        "from_version": previous,
        "schema_version": 1,
        "source_revision": "b" * 40,
        "to_version": new,
    }), encoding="utf-8")
    return contract


def test_approved_transition_seals_a_legacy_selector_with_candidate_revision(
    tmp_path: Path,
) -> None:
    """A normal MSI upgrade must not turn its selected runtime into legacy state."""
    from pc_agent.platform.windows.selector_migration import migrate_initial_selector

    paths = _paths(tmp_path)
    paths.current_path.write_text('{"version":"3.1.76"}', encoding="utf-8")

    assert migrate_initial_selector(
        paths, _provenance_transition_contract(
            tmp_path, previous="3.1.76", new="3.1.77"
        )
    ) == "migrated"
    assert json.loads(paths.current_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "b" * 40,
        "version": "3.1.77",
    }


def test_approved_transition_atomically_migrates_old_initial_selector(
    tmp_path: Path,
) -> None:
    """Removing the old MSI component must not strand current.json on its version."""
    from pc_agent.platform.windows.selector_migration import migrate_initial_selector

    paths = _paths(tmp_path)
    paths.current_path.write_text('{"version":"3.1.76"}', encoding="utf-8")

    outcome = migrate_initial_selector(
        paths, _transition_contract(tmp_path, previous="3.1.76", new="3.1.77")
    )

    assert outcome == "migrated"
    assert json.loads(paths.current_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "a" * 40,
        "version": "3.1.77"
    }
    assert not list(paths.install_root.glob(".current.json.*.tmp"))


@pytest.mark.parametrize("operation", ["rollback", "finalize"])
def test_selector_snapshot_delete_failure_is_flushable_after_restart(tmp_path, monkeypatch, operation):
    from pc_agent.platform.windows import durable_state, selector_migration
    paths = _paths(tmp_path)
    paths.current_path.write_text('{"version":"3.1.77"}')
    snapshot = paths.install_root / selector_migration.ROLLBACK_SNAPSHOT_FILENAME
    snapshot.write_text('{"schema_version":1,"version":"3.1.76"}')
    action = selector_migration.rollback_initial_selector if operation == "rollback" else selector_migration.finalize_initial_selector_migration
    original = durable_state.flush_directory
    def flush(path):
        if not snapshot.exists():
            raise OSError("snapshot metadata failed")
        original(path)
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", flush)
        with pytest.raises(OSError, match="snapshot metadata"):
            action(paths)
    assert not snapshot.exists()
    flushed = []
    monkeypatch.setattr(durable_state, "flush_directory", lambda path: flushed.append(path))
    assert action(paths) == "not_migrated"
    assert flushed == [paths.install_root]
    assert json.loads(paths.current_path.read_text())["version"] == ("3.1.76" if operation == "rollback" else "3.1.77")


def test_approved_transition_accepts_a_revision_bound_initial_selector(
    tmp_path: Path,
) -> None:
    """A later MSI transition cannot strand an initial selector sealed by a new MSI."""
    from pc_agent.platform.windows.selector_migration import migrate_initial_selector

    paths = _paths(tmp_path)
    paths.current_path.write_text(json.dumps({
        "schema_version": 1,
        "source_revision": "a" * 40,
        "version": "3.1.76",
    }), encoding="utf-8")

    assert migrate_initial_selector(
        paths, _transition_contract(tmp_path, previous="3.1.76", new="3.1.77")
    ) == "migrated"


def test_approved_transition_keeps_a_sealed_candidate_selector(
    tmp_path: Path,
) -> None:
    """The migration must not erase MSI provenance already selected by WiX."""
    from pc_agent.platform.windows.selector_migration import migrate_initial_selector

    paths = _paths(tmp_path)
    candidate = paths.versions_root / "3.1.77"
    candidate.mkdir(exist_ok=True)
    (candidate / "pc_agent.exe").write_bytes(b"candidate")
    (candidate / ".endpoint-msi-runtime.json").write_text(json.dumps({
        "component_guid": "D53E70D8-CAD1-4755-9AC8-36164A48C9D5",
        "schema_version": 1,
        "version": "3.1.77",
    }), encoding="utf-8")
    expected = {
        "schema_version": 1,
        "source_revision": "a" * 40,
        "version": "3.1.77",
    }
    paths.current_path.write_text(json.dumps(expected), encoding="utf-8")

    assert migrate_initial_selector(
        paths, _transition_contract(tmp_path, previous="3.1.76", new="3.1.77")
    ) == "migrated_msi_owned"

    assert json.loads(paths.current_path.read_text(encoding="utf-8")) == expected


def test_approved_transition_preserves_a_valid_noninitial_selector(
    tmp_path: Path,
) -> None:
    """An updater-selected valid runtime must not be reset by an MSI transition."""
    from pc_agent.platform.windows.selector_migration import migrate_initial_selector

    paths = _paths(tmp_path)
    selected = paths.versions_root / "3.1.75"
    selected.mkdir()
    (selected / "pc_agent.exe").write_bytes(b"selected")
    (selected / ".endpoint-update.json").write_text(
        '{"version":"3.1.75"}', encoding="utf-8"
    )
    paths.current_path.write_text('{"version":"3.1.75"}', encoding="utf-8")

    outcome = migrate_initial_selector(
        paths, _transition_contract(tmp_path, previous="3.1.76", new="3.1.77")
    )

    assert outcome == "preserved"
    assert json.loads(paths.current_path.read_text(encoding="utf-8")) == {
        "version": "3.1.75"
    }


def test_approved_transition_replaces_an_old_msi_owned_selector(
    tmp_path: Path,
) -> None:
    """A prior MSI initial core must not be preserved until RemoveExistingProducts deletes it."""
    from pc_agent.platform.windows.selector_migration import migrate_initial_selector

    paths = _paths(tmp_path)
    old_msi = paths.versions_root / "3.1.75"
    old_msi.mkdir()
    (old_msi / "pc_agent.exe").write_bytes(b"old-msi")
    (old_msi / ".endpoint-msi-runtime.json").write_text(json.dumps({
        "component_guid": "D53E70D8-CAD1-4755-9AC8-36164A48C9D5",
        "schema_version": 1,
        "version": "3.1.75",
    }), encoding="utf-8")
    paths.current_path.write_text('{"version":"3.1.75"}', encoding="utf-8")

    outcome = migrate_initial_selector(
        paths, _transition_contract(tmp_path, previous="3.1.76", new="3.1.77")
    )

    assert outcome == "migrated_msi_owned"
    assert json.loads(paths.current_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "a" * 40,
        "version": "3.1.77"
    }


def test_transition_rollback_restores_selector_after_later_failure(
    tmp_path: Path,
) -> None:
    """MSI rollback must restore the old selector before its candidate is removed."""
    from pc_agent.platform.windows.selector_migration import (
        migrate_initial_selector,
        rollback_initial_selector,
    )

    paths = _paths(tmp_path)
    paths.current_path.write_text('{"version":"3.1.76"}', encoding="utf-8")
    assert migrate_initial_selector(
        paths, _transition_contract(tmp_path, previous="3.1.76", new="3.1.77")
    ) == "migrated"

    assert rollback_initial_selector(paths) == "restored"
    assert json.loads(paths.current_path.read_text(encoding="utf-8")) == {
        "version": "3.1.76"
    }


def test_approved_transition_rejects_dangling_noninitial_selector(
    tmp_path: Path,
) -> None:
    """Service start must not follow a preserved selector whose runtime is absent."""
    from pc_agent.platform.windows.selector_migration import migrate_initial_selector

    paths = _paths(tmp_path)
    paths.current_path.write_text('{"version":"3.1.75"}', encoding="utf-8")

    with pytest.raises(ValueError, match="selected runtime"):
        migrate_initial_selector(
            paths, _transition_contract(tmp_path, previous="3.1.76", new="3.1.77")
        )

    assert json.loads(paths.current_path.read_text(encoding="utf-8")) == {
        "version": "3.1.75"
    }


def test_service_host_exposes_fixed_no_argument_selector_migration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MSI properties must not choose arbitrary selector or installation paths."""
    from pc_agent.platform.windows import service_launcher

    observed: list[str] = []
    monkeypatch.setattr(
        "pc_agent.platform.windows.selector_migration.migrate_production_selector",
        lambda: observed.append("migrated") or "migrated",
    )

    with pytest.raises(SystemExit):
        service_launcher.main(["--migrate-initial-selector"])
    assert observed == []


def test_service_host_exposes_fixed_tray_status_acl_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MSI cannot redirect the public status ACL action to a caller-selected path."""
    from pc_agent.platform.windows import service_launcher

    observed: list[str] = []
    monkeypatch.setattr(
        "pc_agent.platform.windows.acl.apply_tray_status_acl",
        lambda: observed.append("tray-acl"),
    )

    with pytest.raises(SystemExit):
        service_launcher.main(["--apply-tray-status-acl"])
    assert observed == []


def test_service_host_exposes_fixed_tray_shutdown_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An MSI upgrade may only terminate the installed fixed tray executable."""
    from pc_agent.platform.windows import service_launcher

    observed: list[str] = []
    monkeypatch.setattr(
        service_launcher,
        "stop_tray_companions",
        lambda: observed.append("tray-stopped"),
    )

    with pytest.raises(SystemExit):
        service_launcher.main(["--stop-tray-companions"])
    assert observed == []


def test_tray_shutdown_uses_the_fixed_program_files_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """MSI may extract its FileRef custom-action EXE, so sys.executable is not authority."""
    win32api = pytest.importorskip("win32api", reason="native Windows process handle contract")
    import win32con
    import win32event
    import win32process

    from pc_agent.platform.windows import companion_processes, service_launcher

    tray = tmp_path / "Endpoint Platform" / "Agent" / "EndpointAgentTray.exe"
    tray.parent.mkdir(parents=True)
    tray.write_bytes(b"tray")
    terminated: list[int] = []
    opened_access: list[int] = []

    class _Handle:
        def Close(self) -> None:
            pass

    monkeypatch.setattr(service_launcher.os, "name", "nt")
    monkeypatch.setenv("ProgramW6432", str(tmp_path))
    monkeypatch.setattr(win32process, "EnumProcesses", lambda: [101])
    def open_process(access: int, *_args: object) -> _Handle:
        opened_access.append(access)
        return _Handle()

    monkeypatch.setattr(win32api, "OpenProcess", open_process)

    def unavailable_with_limited_access(*_args: object) -> str:
        raise win32api.error(5, "GetModuleFileNameEx", "Access is denied")

    monkeypatch.setattr(win32process, "GetModuleFileNameEx", unavailable_with_limited_access)
    monkeypatch.setattr(companion_processes, "_process_path", lambda _: str(tray))
    monkeypatch.setattr(
        win32process, "TerminateProcess", lambda _handle, code: terminated.append(code)
    )
    monkeypatch.setattr(
        win32event, "WaitForSingleObject", lambda *_args: win32event.WAIT_OBJECT_0
    )

    service_launcher.stop_tray_companions(WindowsUpdatePaths(tray.parent,tmp_path/'updates/pending_update.json'))

    assert terminated == [0]
    assert win32con.PROCESS_TERMINATE == 1
    assert win32con.SYNCHRONIZE == 1048576
    assert opened_access == [
        win32con.PROCESS_QUERY_LIMITED_INFORMATION
        | win32con.PROCESS_TERMINATE
        | win32con.SYNCHRONIZE
    ]


def test_companion_shutdown_stops_only_installed_tray_and_user_sensor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    win32api = pytest.importorskip("win32api", reason="native Windows process handle contract")
    import win32event
    import win32process

    from pc_agent.platform.windows import companion_processes, service_launcher

    root = tmp_path / "Endpoint Platform" / "Agent"
    root.mkdir(parents=True)
    images = {
        101: root / "EndpointAgentTray.exe",
        102: root / "EndpointUserSensor.exe",
        103: tmp_path / "Elsewhere" / "EndpointUserSensor.exe",
    }
    terminated: list[int] = []

    class Handle:
        def __init__(self, process_id: int) -> None:
            self.process_id = process_id

        def Close(self) -> None:
            pass

    monkeypatch.setattr(service_launcher.os, "name", "nt")
    monkeypatch.setenv("ProgramW6432", str(tmp_path))
    monkeypatch.setattr(win32process, "EnumProcesses", lambda: list(images))
    monkeypatch.setattr(win32api, "OpenProcess", lambda _a, _b, pid: Handle(pid))
    monkeypatch.setattr(companion_processes, "_process_path", lambda h: str(images[h.process_id]))
    monkeypatch.setattr(win32process, "TerminateProcess", lambda h, _c: terminated.append(h.process_id))
    monkeypatch.setattr(win32event, "WaitForSingleObject", lambda *_: win32event.WAIT_OBJECT_0)

    service_launcher.stop_tray_companions(WindowsUpdatePaths(root,tmp_path/'updates/pending_update.json'))

    assert terminated == [101, 102]


def test_companion_image_query_reads_a_limited_process_handle():
    win32api = pytest.importorskip("win32api", reason="native Windows process handle contract")
    import win32con

    from pc_agent.platform.windows import companion_processes

    process = win32api.OpenProcess(
        win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, win32api.GetCurrentProcessId()
    )
    try:
        assert Path(companion_processes._process_path(process)).samefile(win32api.GetModuleFileName(0))
    finally:
        process.Close()


def test_boot_rejects_executable_without_any_ownership_evidence(tmp_path,monkeypatch):
    from pc_agent.platform.windows import service_launcher,installation_provenance
    monkeypatch.setattr(installation_provenance,'_assert_security',lambda _:None)
    paths=_paths(tmp_path)
    paths.current_path.write_text('{"version":"3.1.76"}')
    with pytest.raises(ValueError,match='PROVENANCE_CONFLICT'):
        service_launcher.build_agent_child_command(paths)


@pytest.mark.parametrize("defect", [None, "changed_payload", "incompatible_floor"])
def test_service_file_entry_checks_selected_runtime_ownership(tmp_path, monkeypatch, defect):
    from pc_agent.platform.windows import service_launcher, installation_provenance
    from pc_agent.tests.windows.test_installation_provenance import zip_core

    paths = WindowsUpdatePaths(tmp_path / "Agent", tmp_path / "data/updates/pending_update.json")
    root = zip_core(
        paths, version="3.2.83",
        minimum="3.2.83" if defect == "incompatible_floor" else "3.2.82",
    )
    monkeypatch.setattr(installation_provenance, "_assert_security", lambda _: None)
    entry = runpy.run_path(service_launcher.__file__)
    assert not entry["__package__"]
    command_factory = entry["build_agent_child_command"]
    command_factory.__globals__["AGENT_VERSION"] = "3.2.82"
    if defect == "changed_payload":
        (root / "pc_agent.exe").write_bytes(b"changed")
    if defect:
        with pytest.raises(ValueError, match="PROVENANCE_CONFLICT"):
            command_factory(paths)
    else:
        command = command_factory(paths)
        assert command[0] == str(root / "pc_agent.exe")
        assert command[-2:] == ["--launcher-version", "3.2.82"]


@pytest.mark.parametrize('defect',[None,'missing_receipt','missing_manifest','changed_payload','wrong_source','incompatible_floor','ambiguous_owner'])
def test_boot_requires_complete_zip_ownership(tmp_path,monkeypatch,defect):
    from pc_agent.platform.windows import service_launcher,installation_provenance
    from pc_agent.tests.windows.test_installation_provenance import zip_core
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=zip_core(paths,version='3.2.83',minimum='3.2.83' if defect=='incompatible_floor' else '3.2.82')
    monkeypatch.setattr(installation_provenance,'_assert_security',lambda _:None)
    monkeypatch.setattr(service_launcher,'AGENT_VERSION','3.2.82')
    if defect=='missing_receipt': (root/'.endpoint-update.json').unlink()
    elif defect=='missing_manifest': (root/'endpoint-update-manifest.json').unlink()
    elif defect=='changed_payload': (root/'pc_agent.exe').write_bytes(b'changed')
    elif defect=='wrong_source': paths.current_path.write_text(json.dumps({'schema_version':1,'version':'3.2.83','source_revision':'b'*40}))
    elif defect=='ambiguous_owner': (root/'.endpoint-msi-runtime.json').write_text('{}')
    if defect:
        with pytest.raises(ValueError,match='PROVENANCE_CONFLICT'):
            service_launcher.build_agent_child_command(paths)
    else:
        command=service_launcher.build_agent_child_command(paths)
        assert command[0]==str(root/'pc_agent.exe') and command[-2:]==['--launcher-version','3.2.82']


@pytest.mark.parametrize('where', ['connect', 'phase', 'bad-str', 'event-write'])
def test_installer_helper_unexpected_error_exits_instead_of_windowed_dialog(monkeypatch, where):
    from contextlib import contextmanager
    from pc_agent.platform.windows import service_launcher, installer_transaction_bridge as bridge
    from pc_agent.platform.windows import installer_phase_diagnostics as diagnostics
    reported = []
    def report(phase, error):
        reported.append(phase)
        if where == 'event-write': raise OSError('event delivery failed')
    monkeypatch.setattr(diagnostics, 'report_installer_phase_failure', report)
    class UnexpectedHelperFailure(Exception):
        def __str__(self):
            if where == 'bad-str': raise RuntimeError('message conversion failed')
            return super().__str__()
    @contextmanager
    def owner(*_):
        if where == 'connect': raise UnexpectedHelperFailure('unexpected native error')
        yield object()
    def execute(*_a, **_k): raise UnexpectedHelperFailure('unexpected native error')
    monkeypatch.setattr(bridge, 'owner_authorized_phase', owner)
    monkeypatch.setattr(bridge, 'execute_authorized_phase', execute)
    assert service_launcher.main(['--installer-phase', 'inspect', '--installer-session',
        '11111111-1111-4111-8111-111111111111']) == 1
    assert reported == ['inspect']


@pytest.mark.parametrize('detail, expected', [
    ('UPDATE_IN_PROGRESS', 61), ('UPDATE_STATE_INVALID', 62), ('PROVENANCE_CONFLICT', 63),
])
def test_native_failure_diagnostics_preserve_existing_exit_codes(monkeypatch, detail, expected):
    from contextlib import contextmanager
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    from pc_agent.platform.windows import installer_phase_diagnostics as diagnostics
    from pc_agent.platform.windows import service_launcher
    @contextmanager
    def owner(*_):
        raise ValueError(detail)
        yield
    monkeypatch.setattr(bridge, 'owner_authorized_phase', owner)
    monkeypatch.setattr(diagnostics, 'report_installer_phase_failure', lambda *_: None)
    assert service_launcher.main(['--installer-phase', 'msi-enter', '--installer-session',
        '11111111-1111-4111-8111-111111111111']) == expected


def test_installer_diagnostics_work_from_frozen_script_entry(monkeypatch):
    from contextlib import contextmanager
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    from pc_agent.platform.windows import installer_phase_diagnostics as diagnostics
    from pc_agent.platform.windows import service_launcher
    @contextmanager
    def owner(*_):
        raise ValueError('PROVENANCE_CONFLICT')
        yield
    reported = []
    monkeypatch.setattr(bridge, 'owner_authorized_phase', owner)
    monkeypatch.setattr(diagnostics, 'report_installer_phase_failure', lambda phase, error: reported.append(phase))
    monkeypatch.setattr(service_launcher, '__name__', '__main__')
    monkeypatch.setattr(service_launcher, '__package__', None)
    monkeypatch.setattr(service_launcher, '__spec__', None)
    assert service_launcher.main(['--installer-phase', 'msi-enter', '--installer-session',
        '11111111-1111-4111-8111-111111111111']) == 63
    assert reported == ['msi-enter']

@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job and service pipe")
def test_service_host_stops_only_owned_tree_when_core_ignores_pipe(monkeypatch, tmp_path):
    from contextlib import nullcontext
    import time

    import psutil
    from pc_agent.platform.windows import service_launcher

    paths = _paths(tmp_path)
    selector = b'{"version":"3.1.76"}'
    paths.current_path.write_bytes(selector)
    stopped = []
    monkeypatch.setattr(service_launcher, "_read_state", lambda *_a, **_k: selector)
    monkeypatch.setattr(service_launcher, "core_shutdown_gate", lambda _: nullcontext())
    monkeypatch.setattr(service_launcher, "reserve_core_owner", lambda *_: object())
    monkeypatch.setattr(service_launcher, "record_core_stopped", lambda _, owner: stopped.append(owner))
    ready = tmp_path / "ready"
    script = """
import pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
pathlib.Path(sys.argv[1]).write_text(str(child.pid))
time.sleep(120)
"""
    monkeypatch.setattr(service_launcher, "build_agent_child_command", lambda _, **_kwargs: [
        sys.executable, "-c", script, str(ready),
    ])
    monkeypatch.setattr(service_launcher, "_CORE_STOP_GRACE_SECONDS", 0.25, raising=False)
    updates = []
    monkeypatch.setattr(service_launcher, "trigger_pending_updater", lambda: updates.append(True))
    coordinator = service_launcher.ChildProcessCoordinator(paths)
    exits = []
    thread = threading.Thread(target=lambda: exits.append(coordinator.run()), daemon=True)
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    child = None
    thread.start()
    try:
        end = time.monotonic() + 5
        while (not ready.exists() or not ready.stat().st_size) and time.monotonic() < end:
            time.sleep(0.02)
        child = psutil.Process(int(ready.read_text()))
        coordinator.stop()
        thread.join(3)
        assert not thread.is_alive()
        assert exits == [0]
        assert len(stopped) == 1
        child.wait(timeout=2)
        assert updates == []
        assert unrelated.poll() is None

        # The replacement starts only after the old Job is empty.
        monkeypatch.setattr(service_launcher, "build_agent_child_command", lambda _, **_kwargs: [
            sys.executable, "-c", "raise SystemExit(42)",
        ])
        assert service_launcher.ChildProcessCoordinator(paths).run() == EXIT_UPDATE_PENDING
        assert updates == [True]
        assert len(stopped) == 2
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=2)
        if child is not None and child.is_running():
            child.kill()
        if thread.is_alive():
            process = coordinator._process
            if process is not None:
                terminate = getattr(process, "terminate_tree", None) or process.kill
                terminate()
            thread.join(3)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows frozen service-child protocol")
def test_service_child_exits_when_runtime_ignores_cancellation():
    script = """
import asyncio
from pc_agent.runtime import main
async def runtime(_settings):
    print("ready", flush=True)
    while True:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            continue
main.run_runtime = runtime
main._SERVICE_CHILD_STOP_SECONDS = 0.25
raise SystemExit(main.main([
    "--windows-service-child", "--launcher-version", "3.2.82", "--data-dir", "data",
    "--install-root", "install", "--ca-file", "ca.crt",
]))
"""
    with subprocess.Popen(
        [sys.executable, "-c", script], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process:
        try:
            assert process.communicate(input=b"", timeout=5)[0].strip() == b"ready"
            assert process.returncode == 0
        except subprocess.TimeoutExpired:
            process.kill()
            pytest.fail("Core ignored cancellation and did not exit by the stop deadline")


@pytest.mark.parametrize("active", [0, 1], ids=["zero-count", "forced-stop"])
def test_job_accounting_cannot_replace_verified_process_exit(active):
    from pc_agent.platform.windows import service_launcher

    class OwnedTree:
        def __init__(self):
            self.active = active
            self.termination_requested = False
            self.verified = False

        def active_processes(self):
            return self.active

        def terminate_tree(self):
            self.termination_requested = True
            self.active = 0

        def verify_tree_exited(self, deadline):
            self.verified = True
            return False  # Handles are still unsignalled despite zero active count.

    process = OwnedTree()
    coordinator = service_launcher.ChildProcessCoordinator.__new__(
        service_launcher.ChildProcessCoordinator
    )
    assert coordinator._stop_owned_tree(process) is False
    assert process.termination_requested is bool(active)
    assert process.verified


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Core host")
@pytest.mark.parametrize("selector_changed", [False, True])
def test_reservation_precedes_spawn_and_changed_selector_never_admits_owner(tmp_path, monkeypatch, selector_changed):
    from contextlib import contextmanager
    from pc_agent.platform.windows import core_process, service_launcher

    paths = _paths(tmp_path)
    selector = b'{"version":"3.1.76"}'
    other = b'{"version":"3.1.77"}'
    observed = iter([selector, other, other, selector] if selector_changed else [selector, selector])
    calls = []
    @contextmanager
    def gate(actual_paths):
        assert actual_paths == paths
        calls.append("gate")
        yield
        calls.append("release")

    def build(actual_paths, *, selector_bytes):
        assert actual_paths == paths and selector_bytes in (selector, other)
        calls.append("validated")
        return ["benign-core"]

    def reserve(actual_paths, selector_bytes):
        assert actual_paths == paths and selector_bytes == selector
        assert calls == ["validated", "gate"]
        calls.append("running")
        return object()

    def spawn(command):
        assert command == ["benign-core"]
        calls.append("spawn")
        raise RuntimeError("simulated crash at spawn")

    monkeypatch.setattr(service_launcher, "_read_state", lambda *args, **kwargs: next(observed))
    monkeypatch.setattr(service_launcher, "build_agent_child_command", build)
    monkeypatch.setattr(service_launcher, "core_shutdown_gate", gate)
    monkeypatch.setattr(service_launcher, "reserve_core_owner", reserve)
    monkeypatch.setattr(service_launcher, "record_core_stopped", lambda *_: pytest.fail("unexpected stopped receipt"))
    monkeypatch.setattr(core_process, "WindowsCoreProcess", spawn)
    coordinator = service_launcher.ChildProcessCoordinator(paths)
    if selector_changed:
        with pytest.raises(ValueError, match="selector changed"):
            coordinator.run()
        assert calls == ["validated", "gate", "release", "validated", "gate", "release"]
    else:
        with pytest.raises(RuntimeError, match="crash at spawn"):
            coordinator.run()
        assert calls == ["validated", "gate", "running", "release", "spawn"]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Core host")
@pytest.mark.parametrize("mode", ["restore", "restore_during_validation", "immutable_invalid", "stop"])
def test_pre_admission_restore_revalidates_core_without_reusing_old_command(tmp_path, monkeypatch, mode):
    from contextlib import contextmanager
    from pc_agent.platform.windows import core_process, service_launcher

    paths = _paths(tmp_path)
    candidate = b'{"version":"3.1.77"}'
    restored = b'{"version":"3.1.76"}'
    paths.current_path.write_bytes(candidate)
    coordinator = service_launcher.ChildProcessCoordinator(paths)
    validated, reserved, launched = [], [], []
    gate_held = False

    @contextmanager
    def gate(_paths):
        nonlocal gate_held
        if len(validated) == 1:
            paths.current_path.write_bytes(restored)
        gate_held = True
        try:
            yield
        finally:
            gate_held = False

    def verify_immutable(_paths, selector):
        assert not gate_held
        validated.append(selector["version"])
        if mode == "restore_during_validation" and selector["version"] == "3.1.77":
            from pc_agent.platform.windows.installation_provenance import ProvenanceConflict
            paths.current_path.write_bytes(restored)
            raise ProvenanceConflict()
        if selector["version"] == "3.1.76":
            if mode == "immutable_invalid":
                raise ValueError("restored Core failed immutable validation")
            if mode == "stop":
                coordinator.stop()

    def reserve(_paths, selector_bytes):
        assert gate_held
        reserved.append(selector_bytes)
        return object()

    def spawn(command):
        assert not gate_held
        launched.append(Path(command[0]).parent.name)
        raise RuntimeError("simulated boundary at spawn")

    monkeypatch.setattr(service_launcher, "_read_state", lambda path, *_a, **_k: path.read_bytes())
    monkeypatch.setattr(service_launcher, "_verify_selected_runtime", verify_immutable)
    monkeypatch.setattr(service_launcher, "core_shutdown_gate", gate)
    monkeypatch.setattr(service_launcher, "reserve_core_owner", reserve)
    monkeypatch.setattr(core_process, "WindowsCoreProcess", spawn)

    if mode in ("restore", "restore_during_validation"):
        with pytest.raises(RuntimeError, match="boundary at spawn"):
            coordinator.run()
        assert reserved == [restored] and launched == ["3.1.76"]
    elif mode == "immutable_invalid":
        with pytest.raises(ValueError, match="immutable validation"):
            coordinator.run()
        assert not reserved and not launched
    else:
        assert coordinator.run() == 0
        assert not reserved and not launched
    assert validated == ["3.1.77", "3.1.76"]
