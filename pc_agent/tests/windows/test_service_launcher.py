from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

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
