"""Browser entrypoint contract for Enrollment administration."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser
from endpoint_server.main import create_app


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"enrollment-admin-ui-test-pepper",
        service_token_pepper=b"service-token-pepper",
        session_secret=b"session-secret",
        allowed_agent_cidrs=(),
        allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )


class _Provider:
    @asynccontextmanager
    async def __call__(self):
        yield object()


def _principal() -> AdminPrincipal:
    user_id = uuid4()
    return AdminPrincipal(
        user=AdminUser(
            id=user_id,
            username="first-admin",
            password_digest="unused",
            disabled_at=None,
        ),
        session=AdminSession(
            id=uuid4(),
            admin_user_id=user_id,
            session_digest="unused",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            revoked_at=None,
        ),
    )


@pytest.mark.asyncio
async def test_enrollment_admin_page_uses_the_console_bundle(tmp_path, monkeypatch) -> None:
    from endpoint_server.console import routes as console_routes

    (tmp_path / "index.html").write_text('<html lang="ru">Endpoint Console</html>', encoding="utf-8")
    monkeypatch.setattr(console_routes, "ASSET_ROOT", tmp_path)
    app = create_app(_settings(), session_provider=_Provider())
    app.dependency_overrides[require_admin] = _principal

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local"
    ) as client:
        response = await client.get(
            "/admin/enrollment", cookies={"endpoint_admin_session": "a" * 43}
        )

    assert response.status_code == 200
    assert "Endpoint Console" in response.text
    assert 'lang="ru"' in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "ec_" not in response.text
    assert "ic_" not in response.text
