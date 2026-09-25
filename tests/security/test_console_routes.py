"""Console SecurityEvent reads are paginated and never expose unvalidated metadata."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.base import Base
from endpoint_server.db.models import AdminSession, AdminUser, Device
from endpoint_server.main import create_app
from endpoint_server.security.models import SecurityEvent


@pytest.mark.asyncio
async def test_security_event_console_filters_details_and_redacts_invalid_metadata() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Base.metadata.create_all(
            sync, tables=[Device.__table__, SecurityEvent.__table__],
        ))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"security-device-pepper",
        service_token_pepper=b"security-service-pepper",
        session_secret=b"security-session-secret",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"), endpoint_policy_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    now = datetime.now(UTC)
    device_id, good_id, unsafe_id = uuid4(), uuid4(), uuid4()
    async with sessions() as session:
        session.add(Device(id=device_id, device_identifier="SECURITY-LAB", display_name="Тестовая станция"))
        session.add_all([
            SecurityEvent(
                id=good_id, event_identifier=uuid4(), device_id=device_id,
                event_type="BROWSER_UPLOAD", channel="BROWSER", severity="INFO",
                occurred_at=now - timedelta(minutes=1), received_at=now,
                user_login="operator", policy_id=uuid4(), policy_version=2,
                safe_metadata={"domain": "example.org", "origin": "https://example.org",
                               "browser_family": "yandex", "file_count": 2,
                               "total_bytes": 4096, "mime_categories": ["document"]},
                expires_at=now + timedelta(days=30),
            ),
            SecurityEvent(
                id=unsafe_id, event_identifier=uuid4(), device_id=device_id,
                event_type="BROWSER_PASTE", channel="BROWSER", severity="INFO",
                occurred_at=now - timedelta(minutes=2), received_at=now,
                user_login="operator", policy_id=uuid4(), policy_version=1,
                safe_metadata={"domain": "example.org", "origin": "https://example.org",
                               "browser_family": "chrome", "clipboard_types": ["text"],
                               "page_body": "SYNTHETIC_SECRET_NEVER_EXPOSE"},
                expires_at=now + timedelta(days=30),
            ),
        ])
        await session.commit()
    path = "/api/admin/console/security/events"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        assert (await client.get(path)).status_code == 401
    actor_id = uuid4()
    app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
        user=AdminUser(id=actor_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=actor_id, session_digest="unused",
                             expires_at=now + timedelta(hours=1), revoked_at=None),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        page = await client.get(path, params={"device_id": str(device_id), "limit": 1})
        assert page.status_code == 200, page.text
        assert page.json()["total"] == 2
        assert len(page.json()["data"]) == 1
        assert page.json()["data"][0]["id"] == str(good_id)
        assert page.json()["data"][0]["domain"] == "example.org"
        detail = await client.get(f"{path}/{good_id}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["data"]["safe_metadata"]["file_count"] == 2
        filtered = await client.get(path, params={"event_type": "BROWSER_UPLOAD", "domain": "example.org"})
        assert filtered.json()["total"] == 1
        unsafe = await client.get(f"{path}/{unsafe_id}")
        assert unsafe.status_code == 200, unsafe.text
        assert unsafe.json()["data"]["safe_metadata"] == {}
        assert unsafe.json()["data"]["metadata_valid"] is False
        assert "SYNTHETIC_SECRET_NEVER_EXPOSE" not in unsafe.text
        assert (await client.get(path, params={"limit": 101})).status_code == 422
        assert (await client.get(path, params={"since": "2026-09-25T12:00:00"})).status_code == 422
        assert (await client.get(f"{path}/{uuid4()}")).status_code == 404
    await engine.dispose()
