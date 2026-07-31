"""Immutable ALT update bundle application contracts."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

from pc_agent import alt_update_installer
from pc_agent.alt_update_installer import apply_alt_update


_OPERATION_ID = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_bundle(
    path: Path,
    *,
    version: str = "3.1.77-rc.1",
    source_revision: str = "feedface",
    corrupt_manifest: bool = False,
) -> None:
    files = {
        "launcher": (b"launcher", 0o755),
        "pc_agent/pc_agent": (b"agent", 0o755),
    }
    manifest_files = [
        {
            "path": name,
            "sha256": "0" * 64 if corrupt_manifest and name == "pc_agent/pc_agent" else _sha256(value),
            "mode": f"{mode:04o}",
        }
        for name, (value, mode) in sorted(files.items())
    ]
    manifest = json.dumps(
        {
            "schema_version": 1,
            "version": version,
            "source_revision": source_revision,
            "files": manifest_files,
        },
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, "w:gz") as archive:
        for name, (value, mode) in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(value)
            info.mode = mode
            archive.addfile(info, io.BytesIO(value))
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(manifest))


def _pending(data_root: Path, artifact: Path) -> Path:
    payload = {
        "archive_type": "tar.gz",
        "artifact_path": str(artifact),
        "channel": "canary",
        "operation_id": _OPERATION_ID,
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": _sha256(artifact.read_bytes()),
        "size": artifact.stat().st_size,
        "target": "linux_amd64",
        "version": "3.1.77-rc.1",
    }
    path = data_root / "updates" / "pending_alt_update.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _initial_selector(install_root: Path) -> None:
    (install_root / "versions" / "3.1.76" / "pc_agent").mkdir(parents=True)
    (install_root / "versions" / "3.1.76" / "pc_agent" / "pc_agent").write_bytes(
        b"old-agent"
    )
    (install_root / "current.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "deadbeef",
                "version": "3.1.76",
            }
        ),
        encoding="utf-8",
    )


def test_valid_alt_update_preserves_selector_schema_and_prior_release(
    tmp_path: Path, monkeypatch
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact)

    chmod_calls: list[tuple[Path, int]] = []
    original_chmod = alt_update_installer.os.chmod

    def capture_chmod(path: str | Path, mode: int) -> None:
        chmod_calls.append((Path(path), mode))
        original_chmod(path, mode)

    monkeypatch.setattr(alt_update_installer.os, "chmod", capture_chmod)

    ok, version = apply_alt_update(install_root, data_root, _pending(data_root, artifact))

    assert (ok, version) == (True, "3.1.77-rc.1")
    assert json.loads((install_root / "current.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "feedface",
        "version": "3.1.77-rc.1",
    }
    assert (install_root / "versions" / "3.1.76" / "pc_agent" / "pc_agent").read_bytes() == b"old-agent"
    history = json.loads(
        (data_root / "updates" / "update_history.json").read_text(encoding="utf-8")
    )
    assert history == [
        {
            "operation_id": _OPERATION_ID,
            "previous_version": "3.1.76",
            "success": True,
            "version": "3.1.77-rc.1",
        }
    ]
    assert (install_root / "versions" / "3.1.77-rc.1", 0o755) in chmod_calls
    assert (install_root / "versions" / "3.1.77-rc.1" / "pc_agent", 0o755) in chmod_calls


def test_manifest_hash_mismatch_leaves_active_alt_selector_unchanged(
    tmp_path: Path,
) -> None:
    install_root, data_root = tmp_path / "install", tmp_path / "data"
    _initial_selector(install_root)
    artifact = data_root / "updates" / "downloads" / "candidate.tar.gz"
    artifact.parent.mkdir(parents=True)
    _write_bundle(artifact, corrupt_manifest=True)

    ok, _ = apply_alt_update(install_root, data_root, _pending(data_root, artifact))

    assert ok is False
    assert json.loads((install_root / "current.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "deadbeef",
        "version": "3.1.76",
    }
    assert not (install_root / "versions" / "3.1.77-rc.1").exists()
    assert json.loads(
        (data_root / "updates" / "update_history.json").read_text(encoding="utf-8")
    ) == [
        {
            "operation_id": _OPERATION_ID,
            "success": False,
            "version": "3.1.77-rc.1",
        }
    ]
