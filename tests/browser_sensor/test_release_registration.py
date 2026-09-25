"""Browser release registration validates identity before publishing bytes."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from browser_sensor.tools.build_release import render_update_xml
from endpoint_server.browser_sensor.models import BrowserSensorRelease
from tools import register_browser_sensor_release as registry


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _candidate(root: Path, extension_id: str, version: str = "0.1.0") -> Path:
    candidate = root / "candidate" / version
    candidate.mkdir(parents=True)
    crx = b"synthetic signed CRX; signature checked in separate verifier test"
    manifest = json.dumps({"version": version, "update_url": registry.UPDATE_URL}).encode()
    update = render_update_xml(extension_id, version)
    (candidate / "sensor.crx").write_bytes(crx)
    (candidate / "update.xml").write_bytes(update)
    (candidate / "release.json").write_text(json.dumps({
        "schema_version": "browser_sensor_release_v1",
        "extension_version": version, "extension_id": extension_id,
        "protocol_version": 1, "source_revision": "a" * 40,
        "artifact_filename": "sensor.crx", "artifact_sha256": _digest(crx),
        "manifest_sha256": _digest(manifest),
        "update_manifest_sha256": _digest(update),
        "minimum_agent_version": "3.2.68",
        "created_at": datetime.now(UTC).isoformat(),
    }), encoding="utf-8")
    return candidate


@pytest.mark.asyncio
async def test_registration_stages_immutable_files_and_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "kkkoaifoohdbdaccmnnoagedifflbide"
    candidate = _candidate(tmp_path, extension_id)
    manifest = json.dumps({"version": "0.1.0", "update_url": registry.UPDATE_URL}).encode()
    monkeypatch.setattr(registry, "verify_crx_for_extension_id", lambda *_: {
        "manifest.json": manifest,
    })
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    database_url = f"sqlite+aiosqlite:///{(tmp_path / 'registry.db').as_posix()}"
    engine = create_async_engine(database_url)
    async with engine.begin() as connection:
        await connection.run_sync(BrowserSensorRelease.__table__.create)
    await engine.dispose()

    release = await registry.register_release(
        candidate, database_url=database_url,
        artifact_root=artifact_root, pinned_id=extension_id,
    )
    again = await registry.register_release(
        candidate, database_url=database_url,
        artifact_root=artifact_root, pinned_id=extension_id,
    )
    assert again.id == release.id
    assert {path.name for path in artifact_root.iterdir()} == {
        "browser-sensor-0.1.0.crx",
        "browser-sensor-0.1.0-update.xml",
        "browser-sensor-0.1.0-release.json",
    }
    assert (artifact_root / release.artifact_identifier).read_bytes() == (candidate / "sensor.crx").read_bytes()

    with pytest.raises(ValueError, match="digest"):
        (candidate / "sensor.crx").write_bytes(b"tampered")
        await registry.register_release(
            candidate, database_url=database_url,
            artifact_root=artifact_root, pinned_id=extension_id,
        )
    assert (artifact_root / release.artifact_identifier).read_bytes() != b"tampered"
    (candidate / "sensor.crx").write_bytes(
        b"synthetic signed CRX; signature checked in separate verifier test"
    )
    (artifact_root / release.artifact_identifier).write_bytes(b"corrupt stored artifact")
    with pytest.raises(ValueError, match="unavailable or corrupt"):
        await registry.register_release(
            candidate, database_url=database_url,
            artifact_root=artifact_root, pinned_id=extension_id,
        )

    older = _candidate(tmp_path, extension_id, "0.0.9")
    monkeypatch.setattr(registry, "verify_crx_for_extension_id", lambda *_: {
        "manifest.json": json.dumps({"version": "0.0.9", "update_url": registry.UPDATE_URL}).encode(),
    })
    with pytest.raises(ValueError, match="increase monotonically"):
        await registry.register_release(
            older, database_url=database_url,
            artifact_root=artifact_root, pinned_id=extension_id,
        )


def test_registration_rejects_wrong_identity_and_extra_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "kkkoaifoohdbdaccmnnoagedifflbide"
    candidate = _candidate(tmp_path, extension_id)
    monkeypatch.setattr(registry, "verify_crx_for_extension_id", lambda *_: {
        "manifest.json": json.dumps({"version": "0.1.0", "update_url": registry.UPDATE_URL}).encode(),
    })
    with pytest.raises(ValueError, match="pinned identity"):
        registry.validate_release_inputs(candidate, "a" * 32)
    (candidate / "secret.txt").write_text("unapproved", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected files"):
        registry.validate_release_inputs(candidate, extension_id)
