"""Browser Console entrypoint and session boundary tests."""

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


class _Provider:
    @asynccontextmanager
    async def __call__(self):
        yield _EmptySession()


class _EmptySession:
    async def scalar(self, statement: object) -> None:
        del statement
        return None


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"console-test-device-pepper",
        service_token_pepper=b"console-test-service-pepper",
        session_secret=b"console-test-session-secret",
        allowed_agent_cidrs=(),
        allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )


def _principal() -> AdminPrincipal:
    user_id = uuid4()
    return AdminPrincipal(
        user=AdminUser(
            id=user_id,
            username="operator",
            password_digest="unused",
            scopes=["updates:write"],
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
async def test_console_pages_require_admin_and_login_is_public(tmp_path, monkeypatch) -> None:
    from endpoint_server.console import routes as console_routes

    (tmp_path / "index.html").write_text("<html lang='ru'>Консоль</html>", encoding="utf-8")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "index-test.js").write_text("export default 1", encoding="utf-8")
    monkeypatch.setattr(console_routes, "ASSET_ROOT", tmp_path)
    app = create_app(_settings(), session_provider=_Provider())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local"
    ) as client:
        login = await client.get("/admin/login")
        asset = await client.get("/admin/assets/index-test.js")
        denied = await client.get("/admin")
        invalid = await client.get(
            "/admin", cookies={"endpoint_admin_session": "a" * 43}
        )
        deep_denied = await client.get("/admin/devices/123")
        session_denied = await client.get("/api/admin/console/session")
        fleet_denied = await client.get("/api/admin/console/devices")
        dashboard_denied = await client.get("/api/admin/console/dashboard")
        service_denied = await client.get("/api/v1/devices")

    assert login.status_code == 200
    assert "lang='ru'" in login.text
    assert login.headers["cache-control"] == "no-store"
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert asset.headers["x-content-type-options"] == "nosniff"
    assert denied.status_code == 401
    assert invalid.status_code == 401
    assert deep_denied.status_code == 401
    assert session_denied.status_code == 401
    assert fleet_denied.status_code == 401
    assert dashboard_denied.status_code == 401
    assert service_denied.status_code == 401


@pytest.mark.asyncio
async def test_console_bootstrap_exposes_only_safe_session_projection(tmp_path, monkeypatch) -> None:
    from endpoint_server.console import routes as console_routes

    (tmp_path / "index.html").write_text("<html lang='ru'>Консоль</html>", encoding="utf-8")
    monkeypatch.setattr(console_routes, "ASSET_ROOT", tmp_path)
    app = create_app(_settings(), session_provider=_Provider())
    app.dependency_overrides[require_admin] = _principal
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local"
    ) as client:
        page = await client.get("/admin/devices/123")
        session = await client.get(
            "/api/admin/console/session",
            cookies={"endpoint_admin_session": "a" * 43},
        )

    assert page.status_code == 200
    assert page.headers["x-content-type-options"] == "nosniff"
    assert session.status_code == 200
    assert session.headers["cache-control"] == "no-store"
    assert set(session.json()) == {"username", "scopes", "csrf_token"}
    assert session.json()["username"] == "operator"
    assert session.json()["scopes"] == ["updates:write"]
    assert len(session.json()["csrf_token"]) == 43
    assert "password" not in session.text.lower()
    assert "credential" not in session.text.lower()
