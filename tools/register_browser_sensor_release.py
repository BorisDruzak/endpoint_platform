"""Validate and publish a signed Browser Sensor release into artifact storage.

Run after migration 0031 with DATABASE_URL and ARTIFACT_ROOT from the service
EnvironmentFile. The signing private key is never needed on the server.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from browser_sensor.tools.build_release import (
    UPDATE_URL,
    render_update_xml,
    verify_crx_for_extension_id,
)
from endpoint_server.browser_sensor.models import BrowserSensorRelease
from endpoint_server.db.session import create_session_provider


_SOURCE_FILES = {"manifest.json", "background.js", "content.js", "protocol.js"}
_PINNED_ID_FILE = Path(__file__).resolve().parents[1] / "browser_sensor" / "extension-id.txt"


class BrowserReleaseSidecar(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: str = Field(pattern=r"^browser_sensor_release_v1$")
    extension_version: str = Field(pattern=r"^\d+(?:\.\d+){1,3}$", max_length=32)
    extension_id: str = Field(pattern=r"^[a-p]{32}$")
    protocol_version: int = Field(ge=1, le=1)
    source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    artifact_filename: str = Field(pattern=r"^sensor\.crx$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    update_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    minimum_agent_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include UTC offset")
        return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _version_key(version: str) -> tuple[int, int, int, int]:
    parts = tuple(int(part) for part in version.split("."))
    return (parts + (0, 0, 0, 0))[:4]


def validate_release_inputs(candidate: Path, pinned_id: str) -> BrowserReleaseSidecar:
    """Fail closed before publishing any untrusted candidate bytes."""
    if not re.fullmatch(r"[a-p]{32}", pinned_id):
        raise ValueError("invalid pinned extension ID")
    if not candidate.is_dir() or candidate.is_symlink():
        raise ValueError("release candidate must be a real directory")
    if {p.name for p in candidate.iterdir()} != {"sensor.crx", "update.xml", "release.json"}:
        raise ValueError("release candidate has unexpected files")
    crx, update, sidecar = (candidate / name for name in ("sensor.crx", "update.xml", "release.json"))
    if any(path.is_symlink() or not path.is_file() for path in (crx, update, sidecar)):
        raise ValueError("release candidate contains a non-regular file")
    if crx.stat().st_size > 25 * 1024 * 1024 or update.stat().st_size > 64 * 1024 or sidecar.stat().st_size > 64 * 1024:
        raise ValueError("release candidate exceeds size limit")
    metadata = BrowserReleaseSidecar.model_validate_json(sidecar.read_bytes())
    if metadata.extension_id != pinned_id or candidate.name != metadata.extension_version:
        raise ValueError("release version or extension ID differs from pinned identity")
    if _sha256(crx.read_bytes()) != metadata.artifact_sha256:
        raise ValueError("CRX digest mismatch")
    if update.read_bytes() != render_update_xml(pinned_id, metadata.extension_version):
        raise ValueError("update manifest differs from approved Endpoint HTTPS route")
    if _sha256(update.read_bytes()) != metadata.update_manifest_sha256:
        raise ValueError("update manifest digest mismatch")
    verified = verify_crx_for_extension_id(crx, pinned_id, _SOURCE_FILES)
    if _sha256(verified["manifest.json"]) != metadata.manifest_sha256:
        raise ValueError("extension manifest digest mismatch")
    manifest = json.loads(verified["manifest.json"])
    if manifest.get("version") != metadata.extension_version or manifest.get("update_url") != UPDATE_URL:
        raise ValueError("CRX manifest version or update URL mismatch")
    return metadata


def _install_immutable(source: Path, target: Path, expected_digest: str) -> bool:
    """Install one exact file without replacing an existing artifact."""
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or _sha256(target.read_bytes()) != expected_digest:
            raise ValueError("artifact path is occupied by different bytes")
        return False
    descriptor, temp_name = tempfile.mkstemp(prefix=".browser-release-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as destination, source.open("rb") as original:
            shutil.copyfileobj(original, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        if _sha256(Path(temp_name).read_bytes()) != expected_digest:
            raise ValueError("staged Browser Sensor digest mismatch")
        try:
            os.link(temp_name, target)
        except FileExistsError:
            if target.is_symlink() or not target.is_file() or _sha256(target.read_bytes()) != expected_digest:
                raise ValueError("artifact path changed concurrently") from None
            return False
    finally:
        Path(temp_name).unlink(missing_ok=True)
    return True


async def register_release(
    candidate: Path, *, database_url: str, artifact_root: Path, pinned_id: str
) -> BrowserSensorRelease:
    metadata = validate_release_inputs(candidate, pinned_id)
    sidecar_bytes = (candidate / "release.json").read_bytes()
    if BrowserReleaseSidecar.model_validate_json(sidecar_bytes) != metadata:
        raise ValueError("release metadata changed during validation")
    metadata_digest = _sha256(sidecar_bytes)
    root = artifact_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("ARTIFACT_ROOT is not a directory")
    provider = create_session_provider(database_url)
    try:
        async with provider() as session:
            existing = await session.scalar(select(BrowserSensorRelease).where(
                BrowserSensorRelease.extension_version == metadata.extension_version
            ))
            if existing is not None:
                if (
                    existing.extension_id != metadata.extension_id
                    or existing.artifact_sha256 != metadata.artifact_sha256
                    or existing.update_manifest_sha256 != metadata.update_manifest_sha256
                    or existing.metadata_sha256 != metadata_digest
                ):
                    raise ValueError("release version already has different metadata")
                for name, digest in (
                    (existing.artifact_identifier, existing.artifact_sha256),
                    (existing.update_manifest_identifier, existing.update_manifest_sha256),
                    (existing.metadata_identifier, existing.metadata_sha256),
                ):
                    path = root / name
                    if path.is_symlink() or not path.is_file() or _sha256(path.read_bytes()) != digest:
                        raise ValueError("registered Browser Sensor artifact is unavailable or corrupt")
                return existing
            published_versions = (await session.scalars(
                select(BrowserSensorRelease.extension_version)
            )).all()
            if any(_version_key(other) >= _version_key(metadata.extension_version) for other in published_versions):
                raise ValueError("Browser Sensor version must increase monotonically")
            version = metadata.extension_version
            names = (
                ("sensor.crx", f"browser-sensor-{version}.crx", metadata.artifact_sha256),
                ("update.xml", f"browser-sensor-{version}-update.xml", metadata.update_manifest_sha256),
                ("release.json", f"browser-sensor-{version}-release.json", metadata_digest),
            )
            for source_name, target_name, digest in names:
                _install_immutable(candidate / source_name, root / target_name, digest)
            release = BrowserSensorRelease(
                extension_version=version, extension_id=metadata.extension_id,
                protocol_version=metadata.protocol_version,
                source_revision=metadata.source_revision,
                minimum_agent_version=metadata.minimum_agent_version,
                artifact_identifier=names[0][1], artifact_sha256=metadata.artifact_sha256,
                update_manifest_identifier=names[1][1],
                update_manifest_sha256=metadata.update_manifest_sha256,
                metadata_identifier=names[2][1], metadata_sha256=names[2][2],
                manifest_sha256=metadata.manifest_sha256,
                built_at=metadata.created_at,
            )
            session.add(release)
            await session.commit()
            return release
    finally:
        await provider.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish a signed Browser Sensor release")
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL", "")
    artifact_root = os.environ.get("ARTIFACT_ROOT", "")
    if not database_url or not artifact_root:
        raise ValueError("DATABASE_URL and ARTIFACT_ROOT are required")
    pinned_id = _PINNED_ID_FILE.read_text(encoding="ascii").strip()
    release = asyncio.run(register_release(
        args.candidate, database_url=database_url,
        artifact_root=Path(artifact_root), pinned_id=pinned_id,
    ))
    print(f"registered Browser Sensor release {release.extension_version} ({release.id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
