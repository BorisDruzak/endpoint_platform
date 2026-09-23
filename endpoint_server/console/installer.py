"""Administrator-safe Windows Setup release catalog and verified download."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import WindowsSetupRelease


router = APIRouter(prefix="/api/admin/console/installer", tags=["admin-console-installer"])


class SetupReleaseProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    version: str
    agent_version: str
    filename: str
    setup_sha256: str
    msi_sha256: str
    source_commit: str
    msi_source_commit: str
    authenticode_status: str
    authenticode_publisher: str | None
    msi_authenticode_status: str
    msi_authenticode_publisher: str | None
    created_at: datetime
    retired_at: datetime | None
    download_url: str


class SetupReleasePageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[SetupReleaseProjection]
    total: int
    limit: int
    offset: int


def setup_release_projection(release: WindowsSetupRelease) -> dict[str, object]:
    """Expose signed metadata and a same-origin protected download link."""
    return {
        "id": str(release.id), "version": release.version,
        "agent_version": release.agent_version, "filename": release.filename,
        "setup_sha256": release.setup_sha256, "msi_sha256": release.msi_sha256,
        "source_commit": release.source_commit, "msi_source_commit": release.msi_source_commit,
        "authenticode_status": release.authenticode_status,
        "authenticode_publisher": release.authenticode_publisher,
        "msi_authenticode_status": release.msi_authenticode_status,
        "msi_authenticode_publisher": release.msi_authenticode_publisher,
        "created_at": release.created_at, "retired_at": release.retired_at,
        "download_url": f"/api/admin/console/installer/releases/{release.id}/download",
    }


def _artifact_path(root: Path, identifier: str) -> Path | None:
    if not identifier or Path(identifier).name != identifier:
        return None
    try:
        resolved_root = root.resolve(strict=True)
        path = (resolved_root / identifier).resolve(strict=True)
        path.relative_to(resolved_root)
    except (OSError, ValueError):
        return None
    return path if path.is_file() and not path.is_symlink() else None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@router.get("/releases", response_model=SetupReleasePageResponse)
async def list_setup_releases(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    active_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> SetupReleasePageResponse:
    condition = WindowsSetupRelease.retired_at.is_(None) if active_only else None
    async with request.app.state.session_provider() as session:
        count = select(func.count()).select_from(WindowsSetupRelease)
        listing = select(WindowsSetupRelease)
        if condition is not None:
            count = count.where(condition)
            listing = listing.where(condition)
        total = await session.scalar(count) or 0
        releases = (await session.execute(
            listing.order_by(WindowsSetupRelease.created_at.desc(), WindowsSetupRelease.id.desc())
            .limit(limit).offset(offset)
        )).scalars().all()
    return SetupReleasePageResponse(
        data=[SetupReleaseProjection.model_validate(setup_release_projection(release)) for release in releases],
        total=total, limit=limit, offset=offset,
    )


@router.get("/releases/{release_id}/download", response_model=None)
async def download_setup_release(
    request: Request,
    release_id: UUID,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> FileResponse:
    async with request.app.state.session_provider() as session:
        release = await session.scalar(
            select(WindowsSetupRelease).where(
                WindowsSetupRelease.id == release_id,
                WindowsSetupRelease.retired_at.is_(None),
            )
        )
    if release is None:
        raise HTTPException(status_code=404, detail="Установочный релиз не найден")
    path = _artifact_path(request.app.state.settings.artifact_root, release.artifact_identifier)
    if path is None or path.name != release.filename:
        raise HTTPException(status_code=404, detail="Файл установщика недоступен")
    if await asyncio.to_thread(_sha256, path) != release.setup_sha256:
        raise HTTPException(status_code=503, detail="Проверка установщика не пройдена")
    return FileResponse(
        path, filename=release.filename, media_type="application/octet-stream",
        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
    )
