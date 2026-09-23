"""Windows Setup metadata is immutable and safe for the Console."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.console.installer import setup_release_projection
from endpoint_server.db.models import AdminSession, AdminUser, WindowsSetupRelease
from endpoint_server.main import create_app
from tools.register_windows_setup_release import validate_release_inputs


def test_setup_release_projection_has_no_server_path_or_secret() -> None:
    release = WindowsSetupRelease(
        id=uuid4(), version="3.2.63", agent_version="3.2.63",
        artifact_identifier="EndpointAgentSetup-3.2.63-x64.exe",
        filename="EndpointAgentSetup-3.2.63-x64.exe",
        setup_sha256="a" * 64, msi_sha256="b" * 64,
        source_commit="c" * 40, msi_source_commit="c" * 40,
        authenticode_status="valid", authenticode_publisher="CN=Endpoint",
        msi_authenticode_status="valid", msi_authenticode_publisher="CN=Endpoint",
    )
    projected = setup_release_projection(release)
    assert projected["version"] == "3.2.63"
    assert projected["download_url"] == f"/api/admin/console/installer/releases/{release.id}/download"
    assert "artifact_identifier" not in projected


def test_setup_sidecar_requires_matching_files_and_digests(tmp_path) -> None:
    setup = tmp_path / "EndpointAgentSetup-3.2.63-x64.exe"
    msi = tmp_path / "EndpointAgent-3.2.63-x64.msi"
    sidecar = tmp_path / "release.json"
    setup.write_bytes(b"setup")
    msi.write_bytes(b"msi")
    metadata = {
        "schema_version": "endpoint_windows_setup_release_v1",
        "version": "3.2.63", "agent_version": "3.2.63",
        "source_commit": "a" * 40, "msi_source_commit": "b" * 40,
        "filename": setup.name,
        "setup_sha256": hashlib.sha256(b"setup").hexdigest(),
        "msi_sha256": hashlib.sha256(b"msi").hexdigest(),
        "authenticode_status": "unsigned", "authenticode_publisher": None,
        "msi_authenticode_status": "unsigned", "msi_authenticode_publisher": None,
    }
    sidecar.write_text(json.dumps(metadata), encoding="utf-8")
    assert validate_release_inputs(sidecar, setup, msi).version == "3.2.63"
    setup.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="digest"):
        validate_release_inputs(sidecar, setup, msi)


@pytest.mark.asyncio
async def test_setup_download_requires_admin_and_matching_digest(tmp_path) -> None:
    artifact = tmp_path / "EndpointAgentSetup-3.2.63-x64.exe"
    artifact.write_bytes(b"verified setup")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(WindowsSetupRelease.__table__.create)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    release = WindowsSetupRelease(
        id=uuid4(), version="3.2.63", agent_version="3.2.63",
        artifact_identifier=artifact.name, filename=artifact.name,
        setup_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(), msi_sha256="b" * 64,
        source_commit="a" * 40, msi_source_commit="a" * 40,
        authenticode_status="unsigned", msi_authenticode_status="unsigned",
    )
    async with sessions() as session:
        session.add(release)
        await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"setup-test-device-pepper", service_token_pepper=b"setup-test-service-pepper",
        session_secret=b"setup-test-session-secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path(tmp_path),
    )
    app = create_app(settings, session_provider=sessions)
    url = f"/api/admin/console/installer/releases/{release.id}/download"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        denied = await client.get(url)
    assert denied.status_code == 401
    user_id = uuid4()
    principal = AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=datetime.now(UTC) + timedelta(hours=1), revoked_at=None),
    )
    app.dependency_overrides[require_admin] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        downloaded = await client.get(url)
        artifact.write_bytes(b"tampered")
        corrupt = await client.get(url)
    await engine.dispose()
    assert downloaded.status_code == 200 and downloaded.content == b"verified setup"
    assert downloaded.headers["cache-control"] == "private, no-store"
    assert corrupt.status_code == 503
