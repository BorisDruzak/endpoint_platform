"""Policy authoring and assignment use bounded Console APIs and audit writes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import (
    AdminSession, AdminUser, AuditEvent, Device, PolicyAssignment,
    PolicyDefinition, PolicyVersion,
)
from endpoint_server.main import create_app
from tests.contracts.test_endpoint_policy_v1 import _policy


@pytest.mark.asyncio
async def test_policy_console_versions_assignments_and_audit() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in (
            Device.__table__, AuditEvent.__table__, PolicyDefinition.__table__,
            PolicyVersion.__table__, PolicyAssignment.__table__,
        )])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"policy-device-pepper",
        service_token_pepper=b"policy-service-pepper",
        session_secret=b"policy-session-secret",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"), endpoint_policy_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    paths = app.openapi()["paths"]
    assert paths["/api/admin/console/policies"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("/PolicyPageResponse")
    assert "/api/admin/console/policies/assignments/default" in paths

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        unauthenticated = await client.get("/api/admin/console/policies")
    assert unauthenticated.status_code == 401

    actor_id, device_id = uuid4(), uuid4()
    principal = AdminPrincipal(
        user=AdminUser(id=actor_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=actor_id, session_digest="unused", expires_at=datetime.now(UTC) + timedelta(hours=1), revoked_at=None),
    )
    app.dependency_overrides[require_admin] = lambda: principal
    async with sessions() as session:
        session.add(Device(id=device_id, device_identifier="POLICY-LAB"))
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        invalid = await client.post("/api/admin/console/policies", json={
            "name": "Муниципальная", "policy": _policy(), "free_form": "unsafe",
        })
        created = await client.post("/api/admin/console/policies", json={
            "name": "Муниципальная", "policy": _policy(),
        })
        assert created.status_code == 201, created.text
        version_id = created.json()["data"]["version_id"]
        duplicate_version = await client.post(
            f"/api/admin/console/policies/{created.json()['data']['policy_id']}/versions",
            json={"policy": _policy()},
        )
        second_version = await client.post(
            f"/api/admin/console/policies/{created.json()['data']['policy_id']}/versions",
            json={"policy": _policy(policy_version=2)},
        )
        default = await client.put("/api/admin/console/policies/assignments/default", json={
            "policy_version_id": version_id,
        })
        override = await client.put(
            f"/api/admin/console/policies/assignments/devices/{device_id}",
            json={"policy_version_id": version_id},
        )
        listing = await client.get("/api/admin/console/policies?limit=1")
        invalid_page = await client.get("/api/admin/console/policies?limit=101")
        missing_device = await client.put(
            f"/api/admin/console/policies/assignments/devices/{uuid4()}",
            json={"policy_version_id": version_id},
        )
    async with sessions() as session:
        actions = (await session.scalars(select(AuditEvent.action))).all()
        assignments = (await session.scalars(select(PolicyAssignment))).all()
    await engine.dispose()

    assert invalid.status_code == invalid_page.status_code == 422
    assert duplicate_version.status_code == 409
    assert second_version.status_code == 201
    assert default.status_code == override.status_code == 200
    assert listing.status_code == 200 and listing.json()["total"] == 1
    assert listing.json()["data"][0]["versions_total"] == 2
    assert missing_device.status_code == 404
    assert len(assignments) == 2
    assert actions.count("policy.version.created") == 2
    assert set(actions) == {"policy.version.created", "policy.default.assigned", "policy.device.assigned"}
