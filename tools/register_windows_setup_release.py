"""Register a verified Windows Setup sidecar and binary in artifact storage.

Run from the repository root with DATABASE_URL and ARTIFACT_ROOT exported from the
server EnvironmentFile after migration 0023. Both the Setup EXE and MSI are
required so the two digests in the build sidecar are checked before publication.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from endpoint_server.console.installer import _sha256
from endpoint_server.db.models import WindowsSetupRelease
from endpoint_server.db.session import create_session_provider


_VERSION_RE = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$"
_SHA256_RE = r"^[0-9a-f]{64}$"
_GIT_SHA_RE = r"^[0-9a-f]{40}$"


class SetupSidecar(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^endpoint_windows_setup_release_v1$")
    version: str = Field(pattern=_VERSION_RE)
    agent_version: str = Field(pattern=_VERSION_RE)
    source_commit: str = Field(pattern=_GIT_SHA_RE)
    msi_source_commit: str = Field(pattern=_GIT_SHA_RE)
    filename: str = Field(max_length=256)
    setup_sha256: str = Field(pattern=_SHA256_RE)
    msi_sha256: str = Field(pattern=_SHA256_RE)
    authenticode_status: str = Field(pattern=r"^(valid|unsigned|invalid)$")
    authenticode_publisher: str | None = Field(default=None, max_length=512)
    msi_authenticode_status: str = Field(pattern=r"^(valid|unsigned|invalid)$")
    msi_authenticode_publisher: str | None = Field(default=None, max_length=512)


def validate_release_inputs(sidecar: Path, setup: Path, msi: Path) -> SetupSidecar:
    if not all(path.is_file() and not path.is_symlink() for path in (sidecar, setup, msi)):
        raise ValueError("sidecar, Setup and MSI must be regular files")
    if sidecar.stat().st_size > 64 * 1024:
        raise ValueError("Setup sidecar is too large")
    metadata = SetupSidecar.model_validate_json(sidecar.read_bytes())
    if metadata.filename != f"EndpointAgentSetup-{metadata.version}-x64.exe":
        raise ValueError("Setup filename does not match release version")
    if setup.name != metadata.filename or not msi.name.lower().endswith(".msi"):
        raise ValueError("Setup or MSI filename is invalid")
    if _sha256(setup) != metadata.setup_sha256 or _sha256(msi) != metadata.msi_sha256:
        raise ValueError("Setup or MSI digest does not match sidecar")
    if metadata.authenticode_status == "valid" and not metadata.authenticode_publisher:
        raise ValueError("valid Setup signature requires a publisher")
    if metadata.msi_authenticode_status == "valid" and not metadata.msi_authenticode_publisher:
        raise ValueError("valid MSI signature requires a publisher")
    return metadata


async def register_release(metadata: SetupSidecar, setup: Path, *, database_url: str, artifact_root: Path) -> WindowsSetupRelease:
    root = artifact_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("ARTIFACT_ROOT is not a directory")
    provider = create_session_provider(database_url)
    try:
        async with provider() as session:
            existing = await session.scalar(select(WindowsSetupRelease).where(WindowsSetupRelease.version == metadata.version))
            if existing is not None:
                if existing.setup_sha256 != metadata.setup_sha256:
                    raise ValueError("release version already has a different digest")
                return existing
            target = root / metadata.filename
            if target.exists():
                if not target.is_file() or target.is_symlink() or _sha256(target) != metadata.setup_sha256:
                    raise ValueError("artifact path is occupied by a different file")
            else:
                descriptor, temp_name = tempfile.mkstemp(prefix=".setup-release-", dir=root)
                try:
                    with os.fdopen(descriptor, "wb") as destination, setup.open("rb") as source:
                        shutil.copyfileobj(source, destination, length=1024 * 1024)
                    if _sha256(Path(temp_name)) != metadata.setup_sha256:
                        raise ValueError("staged Setup digest mismatch")
                    os.link(temp_name, target)
                finally:
                    Path(temp_name).unlink(missing_ok=True)
            release = WindowsSetupRelease(
                version=metadata.version, agent_version=metadata.agent_version,
                artifact_identifier=metadata.filename, filename=metadata.filename,
                setup_sha256=metadata.setup_sha256, msi_sha256=metadata.msi_sha256,
                source_commit=metadata.source_commit, msi_source_commit=metadata.msi_source_commit,
                authenticode_status=metadata.authenticode_status,
                authenticode_publisher=metadata.authenticode_publisher,
                msi_authenticode_status=metadata.msi_authenticode_status,
                msi_authenticode_publisher=metadata.msi_authenticode_publisher,
            )
            session.add(release)
            await session.commit()
            return release
    finally:
        await provider.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Register a Windows Setup release")
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--msi", type=Path, required=True)
    args = parser.parse_args()
    metadata = validate_release_inputs(args.sidecar, args.setup, args.msi)
    database_url = os.environ.get("DATABASE_URL", "")
    artifact_root = os.environ.get("ARTIFACT_ROOT", "")
    if not database_url or not artifact_root:
        raise ValueError("DATABASE_URL and ARTIFACT_ROOT are required")
    release = asyncio.run(register_release(metadata, args.setup, database_url=database_url, artifact_root=Path(artifact_root)))
    print(f"registered Windows Setup release {release.version} ({release.id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
