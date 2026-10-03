"""Bounded, safe fleet projections for the browser Console."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
import asyncpg
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, func, literal, select, union_all
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.engine import make_url

from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot, DeviceEvent
from endpoint_server.db.models import AuditEvent, Device, DeviceInstance, DeviceSession, EndpointOperation, EnrollmentRequest, UpdateTarget
from endpoint_server.console.fleet import _SemverKey, dashboard_fleet, device_presence, list_fleet
from endpoint_server.db.base import Base
from endpoint_server.updates.service import _compare_semver
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminSession, AdminUser
from endpoint_server.main import create_app
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY


@pytest.mark.asyncio
async def test_fleet_is_paginated_and_does_not_expose_raw_context() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = [
        Device.__table__, DeviceInstance.__table__, DeviceSession.__table__,
        ContextSnapshot.__table__, ContextCurrent.__table__, UpdateTarget.__table__,
        EnrollmentRequest.__table__, EndpointOperation.__table__,
    ]
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in tables])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    first, second = Device(device_identifier="PC-01", display_name="Первый"), Device(device_identifier="PC-02", display_name="Второй")
    collection_id = uuid4()
    snapshot = ContextSnapshot(
        collection_id=collection_id, device_id=first.id, profile="inventory_v1",
        collected_at=now, raw_payload={"secret": "must-not-leak"},
        normalized_projection={
            "schema_version": "device_context_v1", "profile": "inventory_v1",
            "collected_at": now.isoformat(), "warnings": [],
            "sections": {
                "system": {"hostname": "PC-01", "platform": "windows", "os_name": "Windows 11", "os_version": "11"},
                "hardware": {"cpu_model": "Sample CPU"},
                "memory": {"total_bytes": 17179869184, "module_count": 0, "modules": []},
                "storage": {"physical_devices": []}, "interfaces": [],
            },
        },
    )
    # Defaults are assigned at insert time; explicit IDs keep the fixture small.
    first.id, second.id, snapshot.id = uuid4(), uuid4(), uuid4()
    snapshot.device_id = first.id
    async with sessions() as session:
        session.add_all([first, second, snapshot])
        await session.flush()
        session.add_all([
            DeviceSession(
                device_id=first.id, session_identifier="session-1", expires_at=now + timedelta(hours=1),
                last_seen_at=now, created_at=now,
            ),
            DeviceInstance(device_id=first.id, instance_identifier="instance-1", agent_version="3.2.63", last_result_sequence=0),
            ContextCurrent(device_id=first.id, profile="inventory_v1", snapshot_id=snapshot.id, updated_at=now),
        ])
        await session.commit()
    queries = 0

    def count_query(*_: object) -> None:
        nonlocal queries
        queries += 1

    event.listen(engine.sync_engine, "before_cursor_execute", count_query)
    try:
        async with sessions() as session:
            page = await list_fleet(session, limit=1, offset=0)
            online = await list_fleet(session, limit=10, offset=0, online=True)
            windows = await list_fleet(session, limit=10, offset=0, platform="windows")
            list_queries = queries
            dashboard = await dashboard_fleet(session)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", count_query)
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"fleet-test-device-pepper", service_token_pepper=b"fleet-test-service-pepper",
        session_secret=b"fleet-test-session-secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )
    app = create_app(settings, session_provider=sessions)
    responses = app.openapi()["paths"]
    assert responses["/api/admin/console/devices/{device_id}/context/collections"]["post"]["responses"]["201"]["content"]["application/json"]["schema"]["$ref"].endswith("ConsoleCollectionResponse")
    assert responses["/api/admin/console/context/collections/{collection_id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("ConsoleCollectionResponse")
    user_id = uuid4()
    principal = AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=now + timedelta(hours=1), revoked_at=None),
    )
    app.dependency_overrides[require_admin] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        dashboard_response = await client.get("/api/admin/console/dashboard")
        fleet_response = await client.get("/api/admin/console/devices?limit=1")
        foundation_unknown_response = await client.get("/api/admin/console/devices?foundation_unknown=true&online=true")
        core_filtered = await client.get("/api/admin/console/devices?core_outdated=3.2.82&limit=1&offset=1")
        assert (await client.get("/api/admin/console/devices?core_outdated=invalid")).status_code == 422
        assert (await client.get("/api/admin/console/devices?foundation_outdated=3.02.82")).status_code == 422
    app.dependency_overrides.clear()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        assert (await client.get("/api/admin/console/devices?foundation_unknown=true")).status_code == 401
    await engine.dispose()
    assert page["total"] == 2
    assert len(page["data"]) == 1
    assert online["total"] == 1
    assert online["data"][0]["agent_version"] == "3.2.63"
    assert online["data"][0]["os_name"] == "Windows 11"
    assert online["data"][0]["ram_bytes"] == 17179869184
    assert windows["total"] == 1
    assert dashboard["total"] == 2
    assert dashboard["online"] == 1
    assert dashboard["context_stale"] == 1
    assert {item["version"] for item in dashboard["versions"]} == {"3.2.63", None}
    assert "must-not-leak" not in str(page)
    assert dashboard_response.status_code == fleet_response.status_code == 200
    assert dashboard_response.json()["total"] == fleet_response.json()["total"] == 2
    assert "must-not-leak" not in fleet_response.text
    assert foundation_unknown_response.json()["data"][0]["online"] is True
    assert foundation_unknown_response.json()["data"][0]["launcher_version"] is None
    assert core_filtered.json()["total"] == 1 and core_filtered.json()["data"] == []
    assert list_queries <= 6
    assert queries <= 24


@pytest.mark.asyncio
async def test_console_device_api_uses_session_and_safe_projection() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [
            table.create(sync) for table in (
                Device.__table__, DeviceSession.__table__, DeviceInstance.__table__,
                ContextCollection.__table__, ContextSnapshot.__table__, ContextCurrent.__table__, DeviceEvent.__table__,
                AuditEvent.__table__, UpdateTarget.__table__,
            )
        ])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    device = Device(id=uuid4(), device_identifier="CONSOLE-01", display_name="Console test")
    snapshot = ContextSnapshot(
        id=uuid4(), collection_id=uuid4(), device_id=device.id, profile="session_v1",
        collected_at=now, raw_payload={"device_token": "private-token"},
        normalized_projection={
            "schema_version": "device_context_v1", "profile": "session_v1",
            "collected_at": now.isoformat(), "warnings": [],
            "sections": {"current_user_login": "operator", "interactive_session_present": True},
        },
    )
    inventory_snapshots = [ContextSnapshot(
        id=uuid4(), collection_id=uuid4(), device_id=device.id, profile="inventory_v1",
        collected_at=now - (timedelta(days=2) if index == 0 else timedelta(hours=6)), raw_payload={"secret": "inventory-private"},
        normalized_projection={
            "schema_version": "device_context_v1", "profile": "inventory_v1",
            "collected_at": (now - (timedelta(days=2) if index == 0 else timedelta(hours=6))).isoformat(), "warnings": [],
            "sections": {
                "system": {"hostname": "CONSOLE-01", "platform": "windows", "os_name": "Windows 11", "os_version": "11"},
                "hardware": {}, "memory": {"total_bytes": size, "module_count": 0, "modules": []},
                "storage": {"physical_devices": []}, "interfaces": [],
            },
        },
    ) for index, size in enumerate((8 * 1024 ** 3, 16 * 1024 ** 3))]
    older_inventory = [ContextSnapshot(
        id=uuid4(), collection_id=uuid4(), device_id=device.id, profile="inventory_v1",
        collected_at=now - timedelta(days=8 + index), raw_payload={"secret": "older-private"},
        normalized_projection={
            "schema_version": "device_context_v1", "profile": "inventory_v1",
            "collected_at": (now - timedelta(days=8 + index)).isoformat(), "warnings": [],
            "sections": {
                "system": {"hostname": "CONSOLE-01", "platform": "windows", "os_name": "Windows 11"},
                "hardware": {}, "memory": {"total_bytes": (index + 1) * 1024 ** 3, "module_count": 0, "modules": []},
                "storage": {"physical_devices": []}, "interfaces": [],
            },
        },
    ) for index in range(22)]
    baseline_snapshots = [ContextSnapshot(
        id=uuid4(), collection_id=uuid4(), device_id=device.id, profile="baseline_v1",
        collected_at=now - timedelta(days=1 + 2 * index), raw_payload={"secret": "baseline-private"},
        normalized_projection={
            "schema_version": "device_context_v1", "profile": "baseline_v1",
            "collected_at": (now - timedelta(days=1 + 2 * index)).isoformat(), "warnings": [],
            "sections": {
                "system": {"platform": "windows" if index == 0 else "linux", "distribution": "Test OS", "architecture": "x86_64"},
                "hardware": {"manufacturer": "Test", "model": "Model", "cpu_model": "CPU", "memory_bytes": 1024},
                "storage": [{"stable_key": "disk-1", "model": "Disk", "size_bytes": 1024}],
                "interfaces": [], "software": [],
            },
        },
    ) for index in range(2)]
    async with sessions() as session:
        session.add_all([device, snapshot, *inventory_snapshots, *older_inventory, *baseline_snapshots])
        await session.flush()
        session.add(ContextCurrent(device_id=device.id, profile="session_v1", snapshot_id=snapshot.id, updated_at=now))
        session.add(ContextCurrent(device_id=device.id, profile="inventory_v1", snapshot_id=inventory_snapshots[-1].id, updated_at=now))
        session.add(DeviceEvent(device_id=device.id, event_identifier="context:test:RAM_CHANGED",
            event_kind="RAM_CHANGED", category="context", profile="inventory_v1",
            occurred_at=now, source_key="context:test:RAM_CHANGED", summary_code="RAM_CHANGED",
            details={}, before_hash="a" * 64, after_hash="b" * 64))
        await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"fleet-test-device-pepper", service_token_pepper=b"fleet-test-service-pepper",
        session_secret=b"fleet-test-session-secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"), endpoint_system_primitives_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    for path, model in (
        ("/api/admin/console/dashboard", "ConsoleDashboardResponse"),
        ("/api/admin/console/devices", "ConsoleFleetPageResponse"),
        ("/api/admin/console/devices/{device_id}", "ConsoleDeviceDetailResponse"),
    ):
        schema = app.openapi()["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        assert schema["$ref"].endswith(f"/{model}")
    changes_schema = app.openapi()["paths"]["/api/admin/console/devices/{device_id}/changes"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert changes_schema["$ref"].endswith("/ConsoleChangesPageResponse")
    user_id = uuid4()
    principal = AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=now + timedelta(hours=1), revoked_at=None),
    )
    app.dependency_overrides[require_admin] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        offline = await client.get(f"/api/admin/console/devices/{device.id}")
        await app.state.gateway_connection_registry.register(GatewayConnection(
            device.id, uuid4(), object(), agent_version="3.2.67", platform="windows_amd64",
            effective_capabilities=frozenset({"system.resource_snapshot", "printer.list"}),
        ))
        response = await client.get(f"/api/admin/console/devices/{device.id}")
        changes = await client.get(f"/api/admin/console/devices/{device.id}/changes")
        changes_first = await client.get(f"/api/admin/console/devices/{device.id}/changes?limit=2")
        changes_second = await client.get(f"/api/admin/console/devices/{device.id}/changes?limit=2&offset=2")
        events = await client.get(f"/api/admin/console/devices/{device.id}/events?limit=2&event_kind=RAM_CHANGED")
        history = await client.get(f"/api/admin/console/devices/{device.id}/context/history?profile=inventory_v1&limit=2")
        first_refresh = await client.post(
            f"/api/admin/console/devices/{device.id}/context/collections",
            headers={"Idempotency-Key": "console-refresh-1"}, json={"profile": "health_v1"},
        )
        replay_refresh = await client.post(
            f"/api/admin/console/devices/{device.id}/context/collections",
            headers={"Idempotency-Key": "console-refresh-1"}, json={"profile": "health_v1"},
        )
    async with sessions() as session:
        collection_count = await session.scalar(select(func.count()).select_from(ContextCollection))
        audit_count = await session.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "context.collection_requested"))
    await engine.dispose()
    assert response.status_code == 200
    assert offline.json()["capabilities"] == []
    assert response.json()["capabilities"] == [{
        "capability": "system.resource_snapshot",
        "display_name_ru": MODULE_CAPABILITY_REGISTRY["system.resource_snapshot"].metadata.display_name_ru,
        "category": "system",
    }]
    assert response.json()["device"]["current_user"] == "operator"
    assert response.json()["device"]["hostname"] == "CONSOLE-01"
    assert response.json()["device"]["os_name"] == "Windows 11"
    assert response.json()["device"]["os_version"] == "11"
    assert next(item for item in response.json()["snapshots"] if item["profile"] == "inventory_v1")["fresh"] is True
    assert next(item for item in response.json()["snapshots"] if item["profile"] == "session_v1")["sections"]["current_user_login"] == "operator"
    assert "private-token" not in response.text
    assert "device_token" not in response.text
    assert changes.status_code == 200
    assert any(row["code"] == "RAM_CHANGED" and row["before_value"] == 8 * 1024 ** 3 and row["after_value"] == 16 * 1024 ** 3 for row in changes.json()["data"])
    assert "inventory-private" not in changes.text
    assert changes.json()["has_more"] is True
    assert changes_first.json()["has_more"] is True
    assert changes_second.json()["data"]
    assert [row["after_snapshot_id"] for row in changes_first.json()["data"]] == [
        str(inventory_snapshots[1].id), str(baseline_snapshots[0].id),
    ]
    assert changes_second.json()["data"][0]["after_snapshot_id"] == str(inventory_snapshots[0].id)
    assert {row["after_snapshot_id"] for row in changes_first.json()["data"]}.isdisjoint(
        row["after_snapshot_id"] for row in changes_second.json()["data"]
    )
    assert "older-private" not in changes_second.text
    assert events.status_code == 200
    assert events.json()["data"][0]["summary_code"] == "RAM_CHANGED"
    assert "inventory-private" not in events.text
    assert history.status_code == 200
    assert len(history.json()["data"]) == 2
    assert first_refresh.status_code == 201
    assert replay_refresh.status_code == 200
    assert first_refresh.json()["data"]["id"] == replay_refresh.json()["data"]["id"]
    assert collection_count == audit_count == 1


@pytest_asyncio.fixture(params=["sqlite", "postgresql"])
async def version_engine(request):
    if request.param == "sqlite":
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            yield engine
        finally:
            await engine.dispose()
        return
    admin_url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not admin_url:
        pytest.skip("set ENDPOINT_TEST_POSTGRES_URL to disposable loopback PostgreSQL")
    parsed = make_url(admin_url)
    assert parsed.host in {"127.0.0.1", "localhost", "::1"}
    connection = await asyncpg.connect(admin_url)
    database_name = f"endpoint_console_versions_{uuid4().hex}"
    await connection.execute(f'CREATE DATABASE "{database_name}"')
    engine = create_async_engine(parsed.set(drivername="postgresql+asyncpg", database=database_name))
    try:
        yield engine
    finally:
        await engine.dispose()
        await connection.execute(f'DROP DATABASE "{database_name}"')
        await connection.close()


@pytest.mark.asyncio
async def test_foundation_filters_are_independent_semantic_and_session_only(version_engine) -> None:
    engine = version_engine
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Base.metadata.create_all(sync) if engine.dialect.name == "postgresql" else [table.create(sync) for table in (
            Device.__table__, DeviceInstance.__table__, DeviceSession.__table__,
            ContextSnapshot.__table__, ContextCurrent.__table__, UpdateTarget.__table__,
        )])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    devices = [Device(id=uuid4(), device_identifier=f"VERSION-{index}") for index in range(7)]
    pairs = [("3.2.83", "3.2.82"), ("3.2.81", "3.2.83"), ("3.2.83", "3.2.82"),
             ("3.2.9", "3.2.10"), ("3.2.82-rc.1", "3.2.82+build.1"), ("invalid", "invalid"),
             ("3.2.83", "3.2.82")]
    async with sessions() as session:
        session.add_all(devices)
        await session.flush()
        for index, (device, (core, foundation)) in enumerate(zip(devices, pairs)):
            session.add(DeviceInstance(id=uuid4(), device_id=device.id, instance_identifier=f"current-{index}",
                agent_version=core, launcher_version=foundation, last_seen_at=now, created_at=now))
            if index < 6:
                session.add(DeviceSession(device_id=device.id, session_identifier=f"wss-{index}",
                    expires_at=now + timedelta(hours=1), last_seen_at=now, created_at=now))
        # Latest tied UUID wins even if created_at is older; unknown never falls back.
        session.add(DeviceInstance(id=UUID("ffffffff-ffff-4fff-8fff-ffffffffffff"), device_id=devices[2].id,
            instance_identifier="latest-unknown", agent_version="3.2.83", launcher_version=None,
            last_seen_at=now, created_at=now - timedelta(days=1)))
        session.add(DeviceInstance(device_id=devices[2].id, instance_identifier="null-observation",
            agent_version="99.0.0", launcher_version="99.0.0", last_seen_at=None, created_at=now))
        await session.commit()
    queries = 0
    def count_query(*_: object) -> None:
        nonlocal queries
        queries += 1
    event.listen(engine.sync_engine, "before_cursor_execute", count_query)
    async with sessions() as session:
        page = await list_fleet(session, limit=1)
        assert queries == 2
        assert page["total"] == 7
        assert page["data"][0]["launcher_version"] == "3.2.82"
        assert page["data"][0]["core_newer_than_foundation"] is True
        full = await list_fleet(session, limit=100)
        assert queries == 4  # row count does not grow the query count
        assert all(row["online"] for row in full["data"][:6])
        assert full["data"][6]["online"] is False
        assert full["data"][2]["launcher_version"] is None
        assert full["data"][2]["agent_version"] == "3.2.83"
        assert full["data"][5]["agent_version"] is full["data"][5]["launcher_version"] is None
        presence = await device_presence(session, devices[2].id)
        assert presence["launcher_version"] is None and presence["online"] is True
        core = await list_fleet(session, core_outdated="3.2.82")
        foundation = await list_fleet(session, foundation_outdated="3.2.82")
        newer = await list_fleet(session, core_newer_than_foundation=True)
        missing = await list_fleet(session, foundation_unknown=True)
        assert {row["device_identifier"] for row in core["data"]} == {"VERSION-1", "VERSION-3", "VERSION-4"}
        assert {row["device_identifier"] for row in foundation["data"]} == {"VERSION-3"}
        assert [row["device_identifier"] for row in newer["data"]] == ["VERSION-0", "VERSION-6"]
        assert {row["device_identifier"] for row in missing["data"]} == {"VERSION-2", "VERSION-5"}
        page = await list_fleet(session, core_outdated="3.2.82", limit=1, offset=1)
        assert page["total"] == 3 and page["data"][0]["device_identifier"] == "VERSION-3"
    event.remove(engine.sync_engine, "before_cursor_execute", count_query)


@pytest.mark.asyncio
async def test_semantic_sql_order_matches_recommendation_oracle(version_engine) -> None:
    versions = ["0.0.0", "3.2.9", "3.2.10", "3.2.82-0", "3.2.82-1", "3.2.82-2",
        "3.2.82-10", "3.2.82-Z", "3.2.82-alpha", "3.2.82-alpha-", "3.2.82-alpha.1",
        "3.2.82-alpha.2", "3.2.82-alpha.10", "3.2.82-alpha.beta", "3.2.82-beta",
        "3.2.82", "3.2.82+build.1", "3.2.83", "3.10.0", "10.0.0",
        "1234567890123456789012345678901234567890123456789012345678901234"[:60] + ".0.0",
        "1.0.0-1234567890123456789012345678901234567890123456789012345678"]
    async with version_engine.connect() as connection:
        keys = {value: await connection.scalar(select(_SemverKey(value))) for value in versions}
        ordered = (await connection.execute(union_all(*[
            select(literal(value).label("version"), _SemverKey(value).label("key")) for value in versions
        ]).order_by("key"))).scalars().all()
        assert set(ordered) == set(versions)
        assert all(_compare_semver(left, right) <= 0 for left, right in zip(ordered, ordered[1:]))
        for left in versions:
            for right in versions:
                actual = (keys[left] > keys[right]) - (keys[left] < keys[right])
                assert actual == _compare_semver(left, right), (left, right)
        for invalid in (None, "", "invalid", "03.2.82", "3.2.82-01", "3.2.82\n", "1" * 61 + ".0.0"):
            assert await connection.scalar(select(_SemverKey(invalid))) is None
