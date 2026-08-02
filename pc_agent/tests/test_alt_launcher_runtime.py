"""ALT launcher selection and rollback contracts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from pc_agent.alt_update_installer import apply_alt_update
from pc_agent.launcher import launcher_main


def test_explicit_alt_mode_selects_immutable_pending_path_and_installer(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")

    pending_path, installer = launcher_main.select_update_installation(
        data_root=tmp_path
    )

    assert pending_path == tmp_path / "updates" / "pending_alt_update.json"
    assert installer is apply_alt_update


def test_bad_headless_crash_requests_root_rollback_without_writing_selector(
    monkeypatch, tmp_path: Path
) -> None:
    """Direct selector publication fails under the deployed root-owned boundary."""
    install_root = tmp_path / "install"
    current_path = install_root / "current.json"
    versions = install_root / "versions"
    accepted_binary = versions / "3.1.77" / "endpoint-agent" / "endpoint-agent"
    bad_binary = versions / "3.1.78" / "endpoint-agent" / "endpoint-agent"
    accepted_binary.parent.mkdir(parents=True)
    bad_binary.parent.mkdir(parents=True)
    accepted_binary.write_bytes(b"accepted")
    bad_binary.write_bytes(b"bad")
    accepted_binary.chmod(0o755)
    bad_binary.chmod(0o755)
    (versions / "3.1.77" / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "acceptedheadless",
                "version": "3.1.77",
                "files": [
                    {
                        "path": "endpoint-agent/endpoint-agent",
                        "sha256": hashlib.sha256(b"accepted").hexdigest(),
                        "mode": "0755",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    current_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "badheadless",
                "version": "3.1.78",
            }
        ),
        encoding="utf-8",
    )
    (install_root / "previous.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "acceptedheadless",
                "version": "3.1.77",
            }
        ),
        encoding="utf-8",
    )
    data_root = tmp_path / "data"
    updates = data_root / "updates"
    updates.mkdir(parents=True)
    (updates / "update_history.json").write_text(
        json.dumps(
            [
                {
                    "previous_version": "3.1.77",
                    "success": True,
                    "version": "3.1.78",
                }
            ]
        ),
        encoding="utf-8",
    )
    launches: list[str] = []

    class _FailedProcess:
        def wait(self) -> int:
            return 101

    def fake_popen(argv, **_kwargs):
        launches.append(str(argv[0]))
        return _FailedProcess()

    original_write_text = Path.write_text

    def deny_root_selector_write(path: Path, *args, **kwargs):
        if path == current_path:
            raise PermissionError("root-owned selector")
        return original_write_text(path, *args, **kwargs)

    monotonic_values = iter([0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    monkeypatch.setattr(
        launcher_main, "resolve_data_root", lambda cli_value=None: data_root
    )
    monkeypatch.setattr(
        launcher_main, "resolve_install_root", lambda cli_value=None: install_root
    )
    monkeypatch.setattr(launcher_main.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(launcher_main.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(launcher_main.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(Path, "write_text", deny_root_selector_write)
    monkeypatch.setattr(sys, "argv", ["launcher.py", "--no-gui"])

    with pytest.raises(SystemExit) as exc_info:
        launcher_main.main()

    assert exc_info.value.code == 0
    assert json.loads(current_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "badheadless",
        "version": "3.1.78",
    }
    assert launches == [str(bad_binary)] * launcher_main.IMMEDIATE_CRASH_RETRY_LIMIT
    request = json.loads(
        (updates / "rollback-request.json").read_text(encoding="utf-8")
    )
    assert request == {
        "crashed_source_revision": "badheadless",
        "crashed_version": "3.1.78",
        "rollback_source_revision": "acceptedheadless",
        "rollback_version": "3.1.77",
        "schema_version": "endpoint_alt_rollback_request_v1",
    }
    marker = json.loads(
        (updates / "last_failed_launch.json").read_text(encoding="utf-8")
    )
    assert marker["reason"] == "startup_crash_rollback_requested"

    # The test-only permission seam models the service namespace. The fixed
    # root worker runs outside that namespace and is the only selector writer.
    monkeypatch.setattr(Path, "write_text", original_write_text)
    assert launcher_main.apply_pending_alt_rollback_as_worker(
        install_root=install_root, data_root=data_root
    ) == (True, "3.1.77")
    assert json.loads(current_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "acceptedheadless",
        "version": "3.1.77",
    }
    assert (
        json.loads((updates / "last_failed_launch.json").read_text(encoding="utf-8"))[
            "reason"
        ]
        == "startup_crash_rollback"
    )


def test_alt_agent_defers_a_durable_pending_update_to_the_privileged_worker(
    monkeypatch, tmp_path: Path
) -> None:
    """The service account must never try to publish into root-owned /opt."""
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    pending = tmp_path / "updates" / "pending_alt_update.json"
    pending.parent.mkdir(parents=True)
    pending.write_text("{}", encoding="utf-8")

    assert (
        launcher_main.pending_update_requires_privileged_worker(data_root=tmp_path)
        is True
    )


def test_privileged_alt_worker_applies_once_without_spawning_the_agent(
    monkeypatch, tmp_path: Path
) -> None:
    """Worker mode has one responsibility: consume the durable pending record."""
    pending = tmp_path / "updates" / "pending_alt_update.json"
    pending.parent.mkdir(parents=True)
    pending.write_text("{}", encoding="utf-8")
    applied: list[tuple[Path, Path, Path]] = []

    def fake_apply(
        install_root: Path, data_root: Path, pending_path: Path
    ) -> tuple[bool, str]:
        applied.append((install_root, data_root, pending_path))
        return True, "3.1.79"

    monkeypatch.setattr(launcher_main, "apply_alt_update", fake_apply)

    assert launcher_main.apply_pending_alt_update_as_worker(
        install_root=tmp_path / "install", data_root=tmp_path
    ) == (True, "3.1.79")
    assert applied == [(tmp_path / "install", tmp_path, pending)]


def test_privileged_alt_rollback_cli_consumes_only_the_fixed_request(
    monkeypatch, tmp_path: Path
) -> None:
    """Removing the fixed worker call would strand a durable crash request."""
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    calls: list[tuple[Path, Path]] = []

    def fake_apply(*, install_root: Path, data_root: Path) -> tuple[bool, str]:
        calls.append((install_root, data_root))
        return True, "3.1.77"

    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    monkeypatch.setattr(
        launcher_main,
        "apply_pending_alt_rollback_as_worker",
        fake_apply,
        raising=False,
    )
    monkeypatch.setattr(
        launcher_main, "resolve_install_root", lambda cli_value=None: install_root
    )
    monkeypatch.setattr(
        launcher_main, "resolve_data_root", lambda cli_value=None: data_root
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "launcher.py",
            "--apply-alt-rollback",
            "--install-root",
            str(install_root),
            "--data-dir",
            str(data_root),
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        launcher_main.main()

    assert exc_info.value.code == 0
    assert calls == [(install_root, data_root)]


def test_alt_rollback_cli_requires_alt_mode(monkeypatch, capsys) -> None:
    monkeypatch.delenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", raising=False)
    monkeypatch.setattr(sys, "argv", ["launcher.py", "--apply-alt-rollback"])

    with pytest.raises(SystemExit) as exc_info:
        launcher_main.main()

    assert exc_info.value.code == 2
    assert "requires ENDPOINT_AGENT_ALT_UPDATE_MODE=1" in capsys.readouterr().out


def test_alt_worker_modes_are_mutually_exclusive(monkeypatch, capsys) -> None:
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["launcher.py", "--apply-alt-update", "--apply-alt-rollback"],
    )

    with pytest.raises(SystemExit) as exc_info:
        launcher_main.main()

    assert exc_info.value.code == 2
    assert "mutually exclusive" in capsys.readouterr().out
