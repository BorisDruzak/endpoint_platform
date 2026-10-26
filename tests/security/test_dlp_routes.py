"""The DLP portal uses explicit officer authority, never an admin cookie."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.employee_sessions import require_employee
from endpoint_server.db.base import Base
from endpoint_server.db.models import AuditEvent, Device
from endpoint_server.db.models.identity import ConfirmedIdentity, ScopedRoleGrant
from endpoint_server.policy.models import PolicyDefinition, PolicySensorHealthCurrent, PolicyVersion
from endpoint_server.security.models import SecurityEvent


@pytest.mark.asyncio
async def test_dlp_aliases_require_current_global_officer_and_audit_reads():
    from endpoint_server.security.dlp_routes import router

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
            ConfirmedIdentity.__table__, ScopedRoleGrant.__table__, Device.__table__,
            PolicyDefinition.__table__, PolicyVersion.__table__,
            PolicySensorHealthCurrent.__table__, SecurityEvent.__table__, AuditEvent.__table__,
        ]))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    identity = ConfirmedIdentity(
        id=uuid4(), person_id=uuid4(), issuer="https://sso.example/realms/org",
        subject="Officer", ad_object_guid=uuid4(), state="active", confirmed_at=datetime.now(UTC),
    )
    grant = ScopedRoleGrant(id=uuid4(), identity_id=identity.id, role="dlp_officer", department_id=uuid4(), granted_by=uuid4())
    async with sessions() as session:
        session.add_all([identity, grant])
        await session.commit()
    app = FastAPI()
    app.state.session_provider = sessions
    app.state.settings = SimpleNamespace(endpoint_policy_enabled=True)
    app.include_router(router)
    principal = SimpleNamespace(identity=identity, achieved_acr="low", required_acr="mfa")
    app.dependency_overrides[require_employee] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        # Department-scoped authority must not become an unbounded device read.
        for path in ("/api/dlp/events", f"/api/dlp/events/{uuid4()}", "/api/dlp/policies", "/api/dlp/sensors"):
            result = await client.get(path)
            assert result.status_code == 403, (path, result.text)
        async with sessions() as session:
            stored = await session.get(ScopedRoleGrant, grant.id)
            stored.department_id = None
            await session.commit()
        # A privileged role granted after a password-only login needs step-up.
        assert (await client.get("/api/dlp/events")).status_code == 403
        principal.achieved_acr = "mfa"
        for path in ("/api/dlp/events", "/api/dlp/policies", "/api/dlp/sensors"):
            result = await client.get(path)
            assert result.status_code == 200, (path, result.text)
            assert result.json()["data"] == []
            assert result.headers["cache-control"] == "no-store"
        async with sessions() as session:
            assert await session.scalar(select(func.count()).select_from(AuditEvent)) == 3
            definition_id, version_id = uuid4(), uuid4()
            session.add(PolicyDefinition(id=definition_id, name="DLP pilot"))
            session.add(PolicyVersion(id=version_id, definition_id=definition_id, version=1,
                digest="a"*64, created_by=uuid4(), document={
                    "schema_version": "endpoint_policy_v1", "policy_id": str(definition_id), "policy_version": 1,
                    "activity": {"enabled": True, "idle_threshold_seconds": 300, "foreground_application": True, "browser_context": False},
                    "dlp": {"usb_device_events": "audit", "removable_write_events": "disabled", "print_events": "audit", "browser_upload_events": "disabled", "browser_paste_events": "disabled"},
                    "browser_sensor": {"required": False, "deployment_mode": "external_managed"},
                    "event_retention": {"security_event_days": 30},
                }))
            await session.commit()
        versions = await client.get(f"/api/dlp/policies/{definition_id}/versions")
        assert versions.status_code == 200, versions.text
        assert versions.json()["data"][0]["version_id"] == str(version_id)
        detail = await client.get(f"/api/dlp/policies/{definition_id}/versions/{version_id}")
        assert detail.status_code == 200, detail.text
        policy = detail.json()["data"]["policy"]
        assert policy["dlp"]["usb_device_events"] == "audit"
        assert "activity" not in policy
        assert (await client.get(f"/api/dlp/policies/{uuid4()}/versions/{version_id}")).status_code == 404
        async with sessions() as session:
            stored = await session.get(ScopedRoleGrant, grant.id)
            stored.revoked_at = datetime.now(UTC)
            await session.commit()
        assert (await client.get("/api/dlp/events")).status_code == 403
        app.dependency_overrides[require_employee] = lambda: (_ for _ in ()).throw(HTTPException(401))
        client.cookies.set("endpoint_admin_session", "unrelated")
        assert (await client.get("/api/dlp/events")).status_code == 401
    await engine.dispose()
