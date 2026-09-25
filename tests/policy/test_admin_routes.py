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
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.db.models import (
    AdminSession, AdminUser, AuditEvent, Device, PolicyAssignment,
    PolicyDefinition, PolicyVersion, PolicyDeviceState, BrowserStatusCurrent,
    PolicySensorHealthCurrent,
)
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_server.policy.browser_status import ingest_browser_status
from endpoint_contracts.browser_status import BrowserStatusReportV1
from tests.contracts.test_browser_status_v1 import _report
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
        policy_id = created.json()["data"]["policy_id"]
        policy_summary = await client.get(f"/api/admin/console/policies/{policy_id}")
        missing_policy = await client.get(f"/api/admin/console/policies/{uuid4()}")
        versions = await client.get(f"/api/admin/console/policies/{policy_id}/versions?limit=1")
        version_detail = await client.get(
            f"/api/admin/console/policies/{policy_id}/versions/{second_version.json()['data']['version_id']}"
        )
        default_assignment = await client.get("/api/admin/console/policies/assignments/default")
        wrong_policy_version = await client.get(
            f"/api/admin/console/policies/{uuid4()}/versions/{version_id}"
        )
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
    assert policy_summary.status_code == 200
    assert policy_summary.json()["data"]["name"] == "Муниципальная"
    assert policy_summary.json()["data"]["versions_total"] == 2
    assert missing_policy.status_code == 404
    assert versions.status_code == 200 and versions.json()["total"] == 2
    assert versions.json()["data"][0]["policy_version"] == 2
    assert version_detail.status_code == 200
    assert version_detail.json()["data"]["policy"]["policy_version"] == 2
    assert version_detail.json()["data"]["policy"]["policy_id"] == policy_id
    assert default_assignment.status_code == 200
    assert default_assignment.json()["data"]["policy_version_id"] == version_id
    assert default_assignment.json()["data"]["policy_id"] == policy_id
    assert default_assignment.json()["data"]["policy_version"] == 1
    assert default_assignment.json()["data"]["policy_name"] == "Муниципальная"
    assert wrong_policy_version.status_code == 404
    assert missing_device.status_code == 404
    assert len(assignments) == 2
    assert actions.count("policy.version.created") == 2
    assert set(actions) == {"policy.version.created", "policy.default.assigned", "policy.device.assigned"}


@pytest.mark.asyncio
async def test_policy_device_status_requires_current_browser_capability() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in (
            Device.__table__, PolicyDefinition.__table__, PolicyVersion.__table__,
            PolicyAssignment.__table__, PolicyDeviceState.__table__,
            BrowserStatusCurrent.__table__, PolicySensorHealthCurrent.__table__,
            ContextSnapshot.__table__, ContextCurrent.__table__,
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
    device_id, policy_id, version_id = uuid4(), uuid4(), uuid4()
    document = _policy(browser_sensor={"required": True, "deployment_mode": "agent_managed"})
    document["policy_id"] = str(policy_id)
    from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
    digest = policy_digest(EndpointPolicyV1.model_validate(document))
    async with sessions() as session:
        session.add_all([
            Device(id=device_id, device_identifier="BROWSER-STATUS-LAB"),
            PolicyDefinition(id=policy_id, name="Status lab"),
            PolicyVersion(id=version_id, definition_id=policy_id, version=1,
                          digest=digest, document=document, created_by=uuid4()),
            PolicyAssignment(scope="default", policy_version_id=version_id,
                             assigned_by=uuid4(), assigned_at=datetime.now(UTC)),
            PolicyDeviceState(device_id=device_id, policy_version_id=version_id,
                              policy_digest=digest, status="APPLIED",
                              acknowledged_at=datetime.now(UTC)),
        ])
        await session.commit()
    endpoint = f"/api/admin/console/policies/devices/{device_id}/status"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        assert (await client.get(endpoint)).status_code == 401
    actor_id = uuid4()
    app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
        user=AdminUser(id=actor_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=actor_id, session_digest="unused",
                             expires_at=datetime.now(UTC) + timedelta(hours=1), revoked_at=None),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        disconnected = await client.get(endpoint)
        assert disconnected.status_code == 200, disconnected.text
        assert disconnected.json()["data"]["browser_compliance"] == "STALE"
        await app.state.gateway_connection_registry.register(GatewayConnection(
            device_id=device_id, session_id=uuid4(), websocket=object(), agent_version="3.2.67",
        ))
        unsupported = await client.get(endpoint)
        assert unsupported.json()["data"]["browser_compliance"] == "UNSUPPORTED"
        assert all(item["compliance_state"] == "UNKNOWN" for item in unsupported.json()["data"]["browsers"])
        await app.state.gateway_connection_registry.register(GatewayConnection(
            device_id=device_id, session_id=uuid4(), websocket=object(), agent_version="3.2.70",
            protocol_features=frozenset({"endpoint.browser-status.v1"}),
        ))
        pending = await client.get(endpoint)
        assert pending.json()["data"]["browser_compliance"] == "PARTIAL"
        assert all(item["reason"] == "STATUS_NOT_REPORTED" for item in pending.json()["data"]["browsers"])
        now = datetime.now(UTC)
        observation = _report()
        observation["policy_id"] = policy_id
        observation["observed_at"] = now
        observation["browsers"][0].update({
            "running_state": "RUNNING", "last_running_at": now,
            "extension_version": "0.1.0", "extension_last_seen_at": now,
            "extension_install_type": "ADMIN",
        })
        observation["browsers"][1].update({
            "browser_state": "ABSENT", "policy_owner": "NONE",
            "installation_policy_state": "NOT_APPLIED",
        })
        async with sessions() as session:
            await ingest_browser_status(session, device_id, BrowserStatusReportV1.model_validate(observation), received_at=now)
            await session.commit()
        active = await client.get(endpoint)
        assert active.json()["data"]["browser_compliance"] == "COMPLIANT"
        assert active.json()["data"]["compliance"] == "UNSUPPORTED"
        assert active.json()["data"]["browsers"][0]["extension_install_type"] == "ADMIN"
        assert active.json()["data"]["browsers"][0]["effective_policy_state"] == "APPLIED"
        assert [item["compliance_state"] for item in active.json()["data"]["browsers"]] == ["ACTIVE", "NOT_APPLICABLE"]
        await app.state.gateway_connection_registry.register(GatewayConnection(
            device_id=device_id, session_id=uuid4(), websocket=object(), agent_version="3.2.70",
            protocol_features=frozenset({
                "endpoint.policy.v1", "endpoint.activity.v1", "endpoint.browser-status.v1",
                "endpoint.security-events.v1", "endpoint.sensor-health.v1",
            }),
        ))
        snapshot_id = uuid4()
        activity = {
            "schema_version": "device_context_v1", "profile": "activity_v1",
            "collected_at": now.isoformat(), "warnings": [],
            "sections": {
                "user_login": "operator", "session_state": "ACTIVE", "idle_seconds": 12,
                "foreground": None, "browser": None,
            },
        }
        async with sessions() as session:
            session.add_all([
                ContextSnapshot(
                    id=snapshot_id, collection_id=uuid4(), device_id=device_id,
                    profile="activity_v1", collected_at=now,
                    raw_payload={}, normalized_projection=activity,
                ),
                ContextCurrent(
                    device_id=device_id, profile="activity_v1", snapshot_id=snapshot_id,
                    updated_at=now, last_observed_at=now, last_projection=activity,
                ),
                PolicySensorHealthCurrent(
                    device_id=device_id, observation_id=uuid4(), policy_id=policy_id,
                    policy_version=1, observed_at=now, received_at=now,
                    activity_listener_state="READY", user_sensor_last_seen_at=now,
                    security_spool_state="READY", usb_source_state="READY",
                    print_source_state="READY",
                ),
            ])
            await session.commit()
        healthy = await client.get(endpoint)
        assert healthy.status_code == 200, healthy.text
        assert healthy.json()["data"]["compliance"] == "COMPLIANT"
        assert healthy.json()["data"]["activity_sensor"] == "ACTIVE"
        assert healthy.json()["data"]["browser_sensor"] == "ACTIVE"
        assert healthy.json()["data"]["dlp_sensor"] == "ACTIVE"
        current = await app.state.gateway_connection_registry.get(device_id)
        assert current is not None
        await app.state.gateway_connection_registry.unregister(device_id, current.session_id)
        offline = await client.get(endpoint)
        assert offline.json()["data"]["compliance"] == "STALE"
        assert offline.json()["data"]["browser_compliance"] == "STALE"
        assert offline.json()["data"]["browsers"][0]["extension_version"] == "0.1.0"
        assert offline.json()["data"]["browsers"][0]["compliance_state"] == "UNKNOWN"
        assert offline.json()["data"]["browsers"][0]["effective_policy_state"] == "UNKNOWN"
        assert (await client.get(f"/api/admin/console/policies/devices/{uuid4()}/status")).status_code == 404
    await engine.dispose()
