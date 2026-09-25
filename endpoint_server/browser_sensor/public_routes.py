"""Fixed, unauthenticated HTTPS endpoints for managed Chromium updates."""

from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import select

from endpoint_server.browser_sensor.models import BrowserSensorRelease


router = APIRouter(prefix="/api/v1/browser-sensor", tags=["browser-sensor-release"])
_VERSION = re.compile(r"\d+(?:\.\d+){1,3}\Z")
_MAX_BYTES = {"artifact": 25 * 1024 * 1024, "update": 64 * 1024, "metadata": 64 * 1024}


def _verified_file(root: Path, name: str, digest: str, max_bytes: int) -> bytes:
    """Return the same bounded bytes whose digest was checked."""
    if not name or Path(name).name != name:
        raise HTTPException(status_code=503, detail="Browser Sensor artifact unavailable")
    try:
        resolved_root = root.resolve(strict=True)
        candidate = resolved_root / name
        if candidate.is_symlink() or not candidate.is_file():
            raise OSError("artifact is not a regular file")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
        if resolved.stat().st_size > max_bytes:
            raise OSError("artifact exceeds size limit")
        with resolved.open("rb") as artifact:
            data = artifact.read(max_bytes + 1)
    except (OSError, ValueError):
        raise HTTPException(status_code=503, detail="Browser Sensor artifact unavailable") from None
    if len(data) > max_bytes or hashlib.sha256(data).hexdigest() != digest:
        raise HTTPException(status_code=503, detail="Browser Sensor artifact verification failed")
    return data


def _release_response(root: Path, release: BrowserSensorRelease, kind: str) -> Response:
    version = release.extension_version
    names = {
        "artifact": (release.artifact_identifier, release.artifact_sha256, f"browser-sensor-{version}.crx", "application/x-chrome-extension"),
        "update": (release.update_manifest_identifier, release.update_manifest_sha256, f"browser-sensor-{version}-update.xml", "application/xml"),
        "metadata": (release.metadata_identifier, release.metadata_sha256, f"browser-sensor-{version}-release.json", "application/json"),
    }
    name, digest, expected, media_type = names[kind]
    if name != expected:
        raise HTTPException(status_code=503, detail="Browser Sensor artifact mapping invalid")
    content = _verified_file(root, name, digest, _MAX_BYTES[kind])
    cache = "no-store" if kind == "update" else "public, max-age=31536000, immutable"
    return Response(content=content, media_type=media_type, headers={
        "Cache-Control": cache, "X-Content-Type-Options": "nosniff",
    })


@router.get(
    "/update.xml", response_class=Response,
    responses={
        200: {"description": "Current signed Browser Sensor update manifest", "content": {"application/xml": {"schema": {"type": "string"}}}},
        404: {"description": "No Browser Sensor release published"},
        503: {"description": "Published artifact failed verification"},
    },
)
async def current_update_manifest(request: Request) -> Response:
    async with request.app.state.session_provider() as session:
        release = await session.scalar(
            select(BrowserSensorRelease)
            .where(BrowserSensorRelease.retired_at.is_(None))
            .order_by(BrowserSensorRelease.created_at.desc(), BrowserSensorRelease.id.desc())
            .limit(1)
        )
    if release is None:
        raise HTTPException(status_code=404, detail="Browser Sensor release not published")
    return await asyncio.to_thread(_release_response, request.app.state.settings.artifact_root, release, "update")


async def _versioned_release(request: Request, version: str, kind: str) -> Response:
    if not _VERSION.fullmatch(version):
        raise HTTPException(status_code=404, detail="Browser Sensor release not found")
    async with request.app.state.session_provider() as session:
        release = await session.scalar(
            select(BrowserSensorRelease).where(BrowserSensorRelease.extension_version == version)
        )
    if release is None:
        raise HTTPException(status_code=404, detail="Browser Sensor release not found")
    return await asyncio.to_thread(_release_response, request.app.state.settings.artifact_root, release, kind)


@router.get(
    "/releases/{version}/sensor.crx", response_class=Response,
    responses={
        200: {"description": "Immutable signed CRX3 package", "content": {"application/x-chrome-extension": {"schema": {"type": "string", "format": "binary"}}}},
        404: {"description": "Browser Sensor release not found"},
        503: {"description": "Published artifact failed verification"},
    },
)
async def download_browser_sensor(request: Request, version: str) -> Response:
    return await _versioned_release(request, version, "artifact")


@router.get(
    "/releases/{version}/release.json", response_class=Response,
    responses={
        200: {"description": "Immutable public Browser Sensor release metadata", "content": {"application/json": {"schema": {"type": "object"}}}},
        404: {"description": "Browser Sensor release not found"},
        503: {"description": "Published artifact failed verification"},
    },
)
async def browser_sensor_release_metadata(request: Request, version: str) -> Response:
    return await _versioned_release(request, version, "metadata")
