"""Contracts for the offline, privileged Windows update worker."""

from __future__ import annotations

import hashlib
import inspect
import json
import zipfile
from pathlib import Path

import pytest


def _pending(paths, artifact: Path, **changes: object) -> Path:
    payload: dict[str, object] = {
        "archive_type": "zip",
        "artifact_path": str(artifact),
        "channel": "canary",
        "operation_id": "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "size": artifact.stat().st_size,
        "target": "windows_amd64",
        "version": "3.2.0",
    }
    payload.update(changes)
    paths.pending_path.parent.mkdir(parents=True, exist_ok=True)
    paths.pending_path.write_text(json.dumps(payload), encoding="utf-8")
    return paths.pending_path


def _artifact(path: Path, content: bytes = b"agent") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("pc_agent.exe", content)
        archive.writestr("_internal/runtime.dat", b"runtime")
    return path


class _Acl:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.checked: list[Path] = []

    def assert_update_path(self, path: Path) -> None:
        self.checked.append(path)
        if self.reject:
            raise ValueError("wrong owner or ACL")


def _paths(tmp_path: Path):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    return WindowsUpdatePaths(
        install_root=tmp_path / "install",
        pending_path=tmp_path / "data" / "updates" / "pending_update.json",
    )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"unexpected": True}, "unknown"),
        ({"service_name": "Spooler"}, "unknown"),
        ({"executable": "C:/Windows/System32/cmd.exe"}, "unknown"),
        ({"sha256": "0" * 64}, "hash"),
        ({"size": 1}, "size"),
    ],
)
def test_pending_validator_rejects_untrusted_fields_and_artifact_integrity(
    tmp_path: Path, change: dict[str, object], message: str
) -> None:
    """A root worker must accept only its fixed request shape and bytes."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact, **change)

    with pytest.raises(ValueError, match=message):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_rejects_artifact_outside_fixed_download_root(tmp_path: Path) -> None:
    """An absolute artifact path is safe only under the service-owned downloads root."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(tmp_path / "outside.zip")
    _pending(paths, artifact)

    with pytest.raises(ValueError, match="artifact"):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_rejects_reparse_point_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Path resolution after a reparse point would let an untrusted leaf redirect root."""
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)
    original_lstat = Path.lstat

    class _Details:
        st_file_attributes = 0x400

    def reparse_lstat(path: Path):
        if path == paths.downloads_root:
            return _Details()
        return original_lstat(path)

    monkeypatch.setattr(updater_service.Path, "lstat", reparse_lstat)
    with pytest.raises(ValueError, match="reparse"):
        PendingUpdateValidator(paths, _Acl()).load()


def test_pending_validator_delegates_owner_and_acl_check(tmp_path: Path) -> None:
    """Filesystem shape alone cannot establish Windows ownership or DACL integrity."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip")
    _pending(paths, artifact)

    with pytest.raises(ValueError, match="owner or ACL"):
        PendingUpdateValidator(paths, _Acl(reject=True)).load()


def test_pending_validator_rejects_different_bytes_for_existing_target_version(
    tmp_path: Path,
) -> None:
    """A version directory is immutable; reusing its version label cannot replace bytes."""
    from pc_agent.platform.windows.updater_service import PendingUpdateValidator

    paths = _paths(tmp_path)
    artifact = _artifact(paths.downloads_root / "candidate.zip", b"candidate")
    existing = paths.versions_root / "3.2.0"
    existing.mkdir(parents=True)
    (existing / ".endpoint-update.json").write_text(
        json.dumps({"sha256": "f" * 64, "size": 99, "version": "3.2.0"}),
        encoding="utf-8",
    )
    _pending(paths, artifact)

    with pytest.raises(ValueError, match="collision"):
        PendingUpdateValidator(paths, _Acl()).load()


def test_updater_contract_has_fixed_identity_and_no_network_or_listener_api() -> None:
    """The updater is an offline SCM worker, never an HTTP daemon."""
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.update_paths import (
        INSTALL_ROOT,
        PENDING_UPDATE_PATH,
        UPDATER_SERVICE_NAME,
    )

    source = Path(updater_service.__file__).read_text(encoding="utf-8").lower()
    assert UPDATER_SERVICE_NAME == "EndpointAgentUpdater"
    assert str(PENDING_UPDATE_PATH) == r"C:\ProgramData\Endpoint Platform\Agent\updates\pending_update.json"
    assert str(INSTALL_ROOT) == r"C:\Program Files\Endpoint Platform\Agent"
    assert "aiohttp" not in source
    assert "socket" not in source


def test_updater_default_adapters_remain_import_safe_off_windows() -> None:
    """MSI can construct the demand-start worker before pywin32 is available on test hosts."""
    from pc_agent.platform.windows.updater_service import WindowsUpdater

    assert isinstance(WindowsUpdater(), WindowsUpdater)


def test_updater_install_contract_is_demand_start_with_fixed_start_acl() -> None:
    """No caller-controlled service name may broaden SCM start authority."""
    from pc_agent.platform.windows import service_control

    spec = service_control.WindowsUpdaterServiceInstallSpec()
    assert spec.name == "EndpointAgentUpdater"
    assert spec.start_type == "demand"
    assert spec.start_principals == ("SYSTEM", "Administrators", "NT SERVICE\\EndpointAgent")
    assert list(inspect.signature(service_control.restrict_updater_start_permissions).parameters) == []
