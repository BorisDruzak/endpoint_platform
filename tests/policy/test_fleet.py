"""The policy fleet page filters server-derived compliance before pagination."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.db.models import (
    AdminSession, AdminUser, Device, DeviceInstance, PolicyAssignment,
    PolicyDefinition, PolicyDeviceState, PolicyVersion, BrowserStatusCurrent,
    PolicySensorHealthCurrent,
)
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_server.main import create_app
from tests.contracts.test_endpoint_policy_v1 import _policy


@pytest.mark.asyncio
async def test_policy_fleet_filters_before_paginating_and_uses_live_capabilities() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in (
            Device.__table__, DeviceInstance.__table__, PolicyDefinition.__table__,
            PolicyVersion.__table__, PolicyAssignment.__table__,
            PolicyDeviceState.__table__,
            BrowserStatusCurrent.__table__, PolicySensorHealthCurrent.__table__,
            ContextSnapshot.__table__, ContextCurrent.__table__,
        )])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"fleet-device-pepper",
        service_token_pepper=b"fleet-service-pepper",
        session_secret=b"fleet-session-secret",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"), endpoint_policy_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    policy_id, version_id = uuid4(), uuid4()
    document = _policy()
    document["policy_id"] = str(policy_id)
    document["activity"]["enabled"] = False
    document["browser_sensor"]["required"] = False
    for channel in ("usb_device_events", "print_events", "browser_upload_events", "browser_paste_events"):
        document["dlp"][channel] = "disabled"
    digest = policy_digest(EndpointPolicyV1.model_validate(document))
    now = datetime.now(UTC)
    device_ids = [uuid4() for _ in range(4)]
    async with sessions() as session:
        session.add_all([
            PolicyDefinition(id=policy_id, name="Fleet default"),
            PolicyVersion(
                id=version_id, definition_id=policy_id, version=1,
                digest=digest, document=document, created_by=uuid4(),
            ),
            PolicyAssignment(
                scope="default", policy_version_id=version_id,
                assigned_by=uuid4(), assigned_at=now,
            ),
        ])
        for index, device_id in enumerate(device_ids, 1):
            session.add_all([
                Device(id=device_id, device_identifier=f"FLEET-{index:02d}"),
                DeviceInstance(
                    device_id=device_id, instance_identifier=f"fleet-instance-{index}",
                    agent_version="3.2.70", last_seen_at=now,
                ),
                PolicyDeviceState(
                    device_id=device_id, policy_version_id=version_id,
                    policy_digest=digest, status="APPLIED", acknowledged_at=now,
                ),
            ])
        await session.commit()
    for device_id in device_ids[:2]:
        await app.state.gateway_connection_registry.register(GatewayConnection(
            device_id=device_id, session_id=uuid4(), websocket=object(),
            agent_version="3.2.70", protocol_features=frozenset({"endpoint.policy.v1"}),
        ))
    await app.state.gateway_connection_registry.register(GatewayConnection(
        device_id=device_ids[3], session_id=uuid4(), websocket=object(),
        agent_version="3.2.67", protocol_features=frozenset(),
    ))
    url = "/api/admin/console/policies/fleet"
    async with AsyncClient(transport=ASGITransport(app=app), base_url=settings.public_base_url) as client:
        assert (await client.get(url)).status_code == 401
        actor_id = uuid4()
        app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
            user=AdminUser(
                id=actor_id, username="operator", password_digest="unused",
                scopes=[], disabled_at=None,
            ),
            session=AdminSession(
                id=uuid4(), admin_user_id=actor_id, session_digest="unused",
                expires_at=now + timedelta(hours=1), revoked_at=None,
            ),
        )
        all_devices = await client.get(url)
        compliant_page = await client.get(url, params={
            "compliance": "COMPLIANT", "limit": 1, "offset": 1,
        })
        stale = await client.get(url, params={"compliance": "STALE"})
        unsupported = await client.get(url, params={"compliance": "UNSUPPORTED"})
        invalid = await client.get(url, params={"compliance": "INVALID"})
        wildcard_search = await client.get(url, params={"search": "%"})
    assert all_devices.status_code == compliant_page.status_code == 200
    assert all_devices.json()["total"] == 4
    assert [item["compliance"] for item in all_devices.json()["data"]] == [
        "COMPLIANT", "COMPLIANT", "STALE", "UNSUPPORTED",
    ]
    assert compliant_page.json()["total"] == 2
    assert compliant_page.json()["data"][0]["device_identifier"] == "FLEET-02"
    assert compliant_page.json()["data"][0]["applied_version"] == 1
    assert compliant_page.json()["data"][0]["activity_sensor"] == "NOT_APPLICABLE"
    assert stale.json()["total"] == 1
    assert stale.json()["data"][0]["agent_version"] == "3.2.70"
    assert unsupported.json()["total"] == 1
    assert unsupported.json()["data"][0]["device_identifier"] == "FLEET-04"
    assert invalid.status_code == 422
    assert wildcard_search.status_code == 200
    assert wildcard_search.json()["total"] == 0

    enabled_id, enabled_version_id, partial_device_id = uuid4(), uuid4(), uuid4()
    enabled_document = _policy()
    enabled_document["policy_id"] = str(enabled_id)
    enabled_document["activity"]["enabled"] = True
    enabled_document["browser_sensor"]["required"] = False
    for channel in ("usb_device_events", "print_events", "browser_upload_events", "browser_paste_events"):
        enabled_document["dlp"][channel] = "disabled"
    enabled_digest = policy_digest(EndpointPolicyV1.model_validate(enabled_document))
    async with sessions() as session:
        session.add_all([
            PolicyDefinition(id=enabled_id, name="Activity required"),
            PolicyVersion(
                id=enabled_version_id, definition_id=enabled_id, version=1,
                digest=enabled_digest, document=enabled_document, created_by=uuid4(),
            ),
            PolicyAssignment(
                scope="device", device_id=device_ids[1], policy_version_id=enabled_version_id,
                assigned_by=uuid4(), assigned_at=now,
            ),
            PolicyAssignment(
                scope="device", device_id=partial_device_id,
                policy_version_id=enabled_version_id, assigned_by=uuid4(), assigned_at=now,
            ),
            Device(id=partial_device_id, device_identifier="FLEET-05"),
            PolicyDeviceState(
                device_id=partial_device_id, policy_version_id=enabled_version_id,
                policy_digest=enabled_digest, status="APPLIED", acknowledged_at=now,
            ),
            PolicySensorHealthCurrent(
                device_id=device_ids[1], observation_id=uuid4(), policy_id=enabled_id,
                policy_version=1, observed_at=now, received_at=now,
                activity_listener_state="UNAVAILABLE", user_sensor_last_seen_at=None,
                security_spool_state="READY", usb_source_state="READY",
                print_source_state="READY",
            ),
        ])
        state = await session.scalar(select(PolicyDeviceState).where(
            PolicyDeviceState.device_id == device_ids[1],
        ))
        assert state is not None
        state.policy_version_id = enabled_version_id
        state.policy_digest = enabled_digest
        await session.commit()
    for device_id in (device_ids[1], partial_device_id):
        current = await app.state.gateway_connection_registry.get(device_id)
        if current is not None:
            await app.state.gateway_connection_registry.unregister(device_id, current.session_id)
        await app.state.gateway_connection_registry.register(GatewayConnection(
            device_id=device_id, session_id=uuid4(), websocket=object(),
            agent_version="3.2.70", protocol_features=frozenset({
                "endpoint.policy.v1", "endpoint.activity.v1", "endpoint.sensor-health.v1",
            }),
        ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url=settings.public_base_url) as client:
        partial = await client.get(url, params={"compliance": "PARTIAL"})
        non_compliant = await client.get(url, params={"compliance": "NON_COMPLIANT"})
        search = await client.get(url, params={"search": "FLEET-05"})
    assert partial.status_code == non_compliant.status_code == search.status_code == 200
    assert partial.json()["total"] == 1
    assert partial.json()["data"][0]["device_identifier"] == "FLEET-05"
    assert partial.json()["data"][0]["activity_sensor"] == "UNKNOWN"
    assert non_compliant.json()["total"] == 1
    assert non_compliant.json()["data"][0]["device_identifier"] == "FLEET-02"
    assert non_compliant.json()["data"][0]["activity_sensor"] == "UNAVAILABLE"
    assert search.json()["total"] == 1
    assert search.json()["data"][0]["policy_name"] == "Activity required"
    await engine.dispose()
