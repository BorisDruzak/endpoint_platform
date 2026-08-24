from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from pc_agent.version import EXIT_UPDATE_PENDING
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


def _paths(tmp_path: Path) -> WindowsUpdatePaths:
    install = tmp_path / "install"
    data = tmp_path / "data"
    (install / "versions" / "3.1.76").mkdir(parents=True)
    (install / "versions" / "3.1.77").mkdir(parents=True)
    (install / "versions" / "3.1.76" / "pc_agent.exe").write_bytes(b"old")
    (install / "versions" / "3.1.77" / "pc_agent.exe").write_bytes(b"new")
    data.mkdir()
    return WindowsUpdatePaths(install, data / "updates" / "pending_update.json")


def test_service_host_resolves_current_selector_on_each_start(tmp_path: Path) -> None:
    """Pinning SCM to the initial core would make an applied update ineffective."""
    from pc_agent.platform.windows.service_launcher import build_agent_child_command

    paths = _paths(tmp_path)
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
        "--data-dir", "data",
        "--install-root", "install",
        "--ca-file", "ca.crt",
    ]) == 0
    assert cancelled.is_set()


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
    '--ca-file', 'ca.crt',
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
        "to_version": new,
    }), encoding="utf-8")
    return contract


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
        "version": "3.1.77"
    }
    assert not list(paths.install_root.glob(".current.json.*.tmp"))


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

    assert service_launcher.main(["--migrate-initial-selector"]) == 0
    assert observed == ["migrated"]
