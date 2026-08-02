"""Lifecycle and rollback contracts for EndpointAgentUpdater."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path


def _setup(tmp_path: Path):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "data" / "updates" / "pending_update.json")
    old = paths.versions_root / "3.1.0"
    old.mkdir(parents=True)
    (old / "pc_agent.exe").write_bytes(b"old")
    paths.install_root.mkdir(parents=True, exist_ok=True)
    paths.current_path.write_text(json.dumps({"version": "3.1.0"}), encoding="utf-8")
    artifact = paths.downloads_root / "candidate.zip"
    artifact.parent.mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("pc_agent.exe", b"new")
        archive.writestr("_internal/runtime.dat", b"runtime")
    payload = {
        "archive_type": "zip", "artifact_path": str(artifact), "channel": "canary",
        "operation_id": "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e", "requested_by": "gateway",
        "requested_reason": "scheduled_rollout", "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "size": artifact.stat().st_size, "target": "windows_amd64", "version": "3.2.0",
    }
    paths.pending_path.write_text(json.dumps(payload), encoding="utf-8")
    return paths


class _Acl:
    def assert_update_path(self, _path: Path) -> None: pass


class _Service:
    def __init__(self, *, crash: bool = False) -> None:
        self.events: list[str] = []
        self.crash = crash
    def stop(self) -> None: self.events.append("stop")
    def start(self) -> None: self.events.append("start")
    def crashed_early(self) -> bool: return self.crash


class _Verifier:
    def __init__(self, events: list[str]) -> None: self.events = events
    def verify(self, executable: Path) -> bool:
        assert executable.name == "pc_agent.exe"
        self.events.append("verify")
        return True


class _FailingVerifier(_Verifier):
    def verify(self, executable: Path) -> bool:
        super().verify(executable)
        return False


class _Confirmation:
    def __init__(self, events: list[str], *, confirmed: bool) -> None:
        self.events, self.confirmed = events, confirmed
    def wait_for_startup(self, *, version: str, deadline_seconds: int) -> bool:
        assert version == "3.2.0" and deadline_seconds > 0
        self.events.append("confirmation")
        return self.confirmed


def test_updater_applies_then_waits_for_server_side_startup_confirmation(tmp_path: Path) -> None:
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths, service = _setup(tmp_path), _Service()
    updater = WindowsUpdater(paths, acl=_Acl(), service=service, verifier=_Verifier(service.events), confirmation=_Confirmation(service.events, confirmed=True))

    assert updater.run_once().status == "applied"
    assert service.events == ["stop", "verify", "start", "confirmation"]
    assert json.loads(paths.current_path.read_text()) == {"version": "3.2.0"}
    assert not paths.pending_path.exists()


def test_updater_rolls_back_selector_when_startup_confirmation_deadline_expires(tmp_path: Path) -> None:
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths, service = _setup(tmp_path), _Service()
    updater = WindowsUpdater(paths, acl=_Acl(), service=service, verifier=_Verifier(service.events), confirmation=_Confirmation(service.events, confirmed=False))

    assert updater.run_once().status == "rolled_back"
    assert service.events == ["stop", "verify", "start", "confirmation", "start"]
    assert json.loads(paths.current_path.read_text()) == {"version": "3.1.0"}


def test_updater_rolls_back_before_confirmation_after_an_early_crash(tmp_path: Path) -> None:
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths, service = _setup(tmp_path), _Service(crash=True)
    updater = WindowsUpdater(paths, acl=_Acl(), service=service, verifier=_Verifier(service.events), confirmation=_Confirmation(service.events, confirmed=True))

    assert updater.run_once().status == "rolled_back"
    assert service.events == ["stop", "verify", "start", "start"]
    assert json.loads(paths.current_path.read_text()) == {"version": "3.1.0"}


def test_updater_restarts_the_previous_agent_when_new_verify_fails(tmp_path: Path) -> None:
    """A failed candidate must not leave EndpointAgent stopped after the handoff."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    paths, service = _setup(tmp_path), _Service()
    updater = WindowsUpdater(paths, acl=_Acl(), service=service, verifier=_FailingVerifier(service.events), confirmation=_Confirmation(service.events, confirmed=True))

    assert updater.run_once().status == "rejected"
    assert service.events == ["stop", "verify", "start"]
    assert json.loads(paths.current_path.read_text()) == {"version": "3.1.0"}
    assert not list((paths.versions_root / "_staging").glob("*"))
