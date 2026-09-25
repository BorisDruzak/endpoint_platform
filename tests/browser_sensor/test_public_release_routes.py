"""Public browser updates serve only registered, digest-verified releases."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.config import Settings
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import AdminSession, AdminUser, BrowserSensorRelease
from endpoint_server.main import create_app


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.mark.asyncio
async def test_public_browser_release_routes_are_registered_and_verified(tmp_path: Path) -> None:
    version = "0.1.0"
    extension_id = "kkkoaifoohdbdaccmnnoagedifflbide"
    crx = b"signed test CRX"
    update = (
        f'<gupdate><app appid="{extension_id}"><updatecheck '
        f'codebase="https://endpoint.sosnadmin.local/api/v1/browser-sensor/releases/{version}/sensor.crx" '
        f'version="{version}"/></app></gupdate>'
    ).encode()
    metadata = json.dumps({
        "schema_version": "browser_sensor_release_v1",
        "extension_version": version,
        "extension_id": extension_id,
        "protocol_version": 1,
        "source_revision": "a" * 40,
        "artifact_filename": "sensor.crx",
        "artifact_sha256": _digest(crx),
        "manifest_sha256": "b" * 64,
        "update_manifest_sha256": _digest(update),
        "minimum_agent_version": "3.2.68",
        "created_at": datetime.now(UTC).isoformat(),
    }, sort_keys=True).encode()
    paths = {
        "artifact": tmp_path / f"browser-sensor-{version}.crx",
        "update": tmp_path / f"browser-sensor-{version}-update.xml",
        "metadata": tmp_path / f"browser-sensor-{version}-release.json",
    }
    for key, data in (("artifact", crx), ("update", update), ("metadata", metadata)):
        paths[key].write_bytes(data)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(BrowserSensorRelease.__table__.create)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    release = BrowserSensorRelease(
        extension_version=version, extension_id=extension_id, protocol_version=1,
        source_revision="a" * 40, minimum_agent_version="3.2.68",
        artifact_identifier=paths["artifact"].name, artifact_sha256=_digest(crx),
        update_manifest_identifier=paths["update"].name,
        update_manifest_sha256=_digest(update),
        metadata_identifier=paths["metadata"].name, metadata_sha256=_digest(metadata),
        manifest_sha256="b" * 64, built_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"browser-test-device-pepper",
        service_token_pepper=b"browser-test-service-pepper",
        session_secret=b"browser-test-session-secret",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(), artifact_root=tmp_path,
    )
    app = create_app(settings, session_provider=sessions)
    async with AsyncClient(transport=ASGITransport(app=app), base_url=settings.public_base_url) as client:
        unpublished = await client.get("/api/v1/browser-sensor/update.xml")
        async with sessions() as session:
            session.add(release)
            await session.commit()
        feed = await client.get("/api/v1/browser-sensor/update.xml")
        package = await client.get(f"/api/v1/browser-sensor/releases/{version}/sensor.crx")
        sidecar = await client.get(f"/api/v1/browser-sensor/releases/{version}/release.json")
        admin_denied = await client.get("/api/admin/console/browser-sensor/release")
        user_id = uuid4()
        app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
            user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
            session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=datetime.now(UTC) + timedelta(hours=1), revoked_at=None),
        )
        admin_release = await client.get("/api/admin/console/browser-sensor/release")
        missing = await client.get("/api/v1/browser-sensor/releases/0.1.1/sensor.crx")
        listing = await client.get("/api/v1/browser-sensor/releases")
        paths["artifact"].write_bytes(b"tampered")
        corrupt = await client.get(f"/api/v1/browser-sensor/releases/{version}/sensor.crx")
        paths["update"].write_bytes(b"tampered")
        corrupt_feed = await client.get("/api/v1/browser-sensor/update.xml")
        release.retired_at = datetime.now(UTC) + timedelta(seconds=1)
        async with sessions() as session:
            await session.merge(release)
            await session.commit()
        retired_feed = await client.get("/api/v1/browser-sensor/update.xml")
    await engine.dispose()
    assert unpublished.status_code == 404
    assert feed.status_code == 200 and feed.content == update
    assert feed.headers["cache-control"] == "no-store"
    assert package.status_code == 200 and package.content == crx
    assert package.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert sidecar.status_code == 200 and sidecar.content == metadata
    assert admin_denied.status_code == 401
    assert admin_release.status_code == 200
    assert admin_release.json()["extension_id"] == extension_id
    assert admin_release.json()["artifact_sha256"] == _digest(crx)
    assert "artifact_identifier" not in admin_release.json()
    assert missing.status_code == 404 and listing.status_code == 404
    assert corrupt.status_code == 503
    assert corrupt_feed.status_code == 503
    assert retired_feed.status_code == 404
