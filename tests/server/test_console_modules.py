"""Admin Module Workbench reuses the guarded domain lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import (
    AdminSession, AdminUser, AuditEvent, Device, EndpointOperation,
    ModuleDefinition, ModuleLiveTest, ModuleOperationStep, ModuleValidationRun, ModuleVersion,
    ServiceClient,
)
from endpoint_server.main import create_app
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_contracts.capabilities import module_capability_catalog


@pytest.mark.asyncio
async def test_admin_module_catalog_draft_validation_and_fake_lab_rejection() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in (
            ServiceClient.__table__, Device.__table__, AuditEvent.__table__,
            ModuleDefinition.__table__, ModuleVersion.__table__,
            ModuleValidationRun.__table__, EndpointOperation.__table__,
            ModuleLiveTest.__table__,
        )])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"modules-test-device-pepper",
        service_token_pepper=b"modules-test-service-pepper",
        session_secret=b"modules-test-session-secret",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"), endpoint_module_platform_enabled=True,
        endpoint_module_execution_enabled=True, endpoint_network_primitives_enabled=True,
        endpoint_network_probe_allowed_suffixes=(".example.test",),
        endpoint_operations_api_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    user_id = uuid4()
    principal = AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=datetime.now(UTC) + timedelta(hours=1), revoked_at=None),
    )
    app.dependency_overrides[require_admin] = lambda: principal
    lab_device = Device(id=uuid4(), device_identifier="LAB-01", display_name="Lab device")
    second_lab_device = Device(id=uuid4(), device_identifier="LAB-02", display_name="Second lab")
    async with sessions() as session:
        session.add_all([lab_device, second_lab_device]); await session.commit()
    await app.state.gateway_connection_registry.register(GatewayConnection(
        lab_device.id, uuid4(), object(), agent_version="3.2.63", platform="linux_amd64",
        effective_capabilities=frozenset({"dns.resolve"}),
    ))
    await app.state.gateway_connection_registry.register(GatewayConnection(
        second_lab_device.id, uuid4(), object(), agent_version="3.2.63", platform="linux_amd64",
        effective_capabilities=frozenset({"dns.resolve"}),
    ))
    recipe = {
        "schema_version": "endpoint_recipe_module_v1", "module_key": "network.basic.check",
        "supported_platforms": ["linux_amd64"],
        "inputs": [{"name": "target", "value_type": "string"}],
        "steps": [{"step_id": "dns", "capability": "dns.resolve", "parameters": {
            "target": {"kind": "input", "name": "target"},
            "family": {"kind": "literal", "value": "any"},
        }}],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        catalog = await client.get("/api/admin/console/module-capabilities")
        invalid = await client.post("/api/admin/console/modules/versions", json={
            "schema_version": "module_version_create_v1", "display_name": "Bad", "version": "1.0.0",
            "recipe": {**recipe, "steps": [{"step_id": "bad", "capability": "shell.exec", "parameters": {}}]},
        })
        created = await client.post("/api/admin/console/modules/versions", json={
            "schema_version": "module_version_create_v1", "display_name": "Network Check",
            "version": "1.0.0", "recipe": recipe,
        })
        listing = await client.get("/api/admin/console/modules")
        validated = await client.post("/api/admin/console/modules/network.basic.check/versions/1.0.0/validate")
        lab_devices = await client.get("/api/admin/console/modules/network.basic.check/versions/1.0.0/lab-devices?limit=1")
        next_lab_devices = await client.get("/api/admin/console/modules/network.basic.check/versions/1.0.0/lab-devices?limit=1&offset=1")
        detail = await client.get("/api/admin/console/modules/network.basic.check/versions/1.0.0")
        fake_evidence = await client.post(f"/api/admin/console/modules/network.basic.check/versions/1.0.0/lab-evidence/{uuid4()}")
        premature_publish = await client.post("/api/admin/console/modules/network.basic.check/versions/1.0.0/publish")
    await engine.dispose()
    assert catalog.status_code == 200 and len(catalog.json()["data"]["items"]) == 6
    catalog_items = catalog.json()["data"]["items"]
    assert {item["capability"] for item in catalog_items} == {
        item.capability for item in module_capability_catalog().items
    }
    assert all(item["display_name"] and any(chr(0x0400) <= char.lower() <= chr(0x04ff) for char in item["display_name"]) for item in catalog_items)
    assert all("risk" in item and "consent_required" in item and "parameters" in item for item in catalog_items)
    assert invalid.status_code == 422
    assert created.status_code == 201
    assert listing.status_code == 200 and listing.json()["total"] == 1
    assert listing.json()["data"][0]["versions"][0]["version"] == "1.0.0"
    assert validated.status_code == 200 and validated.json()["data"]["status"] == "succeeded"
    assert lab_devices.status_code == 200 and lab_devices.json()["data"][0]["id"] == str(lab_device.id)
    assert lab_devices.json()["total"] == next_lab_devices.json()["total"] == 2
    assert next_lab_devices.json()["data"][0]["id"] == str(second_lab_device.id)
    assert detail.status_code == 200 and detail.json()["data"]["validations"][0]["status"] == "succeeded"
    assert fake_evidence.status_code == 409
    assert premature_publish.status_code == 409


@pytest.mark.asyncio
async def test_device_published_module_runs_network_and_read_only_steps() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in (
            ServiceClient.__table__, Device.__table__, AuditEvent.__table__,
            ModuleDefinition.__table__, ModuleVersion.__table__,
            EndpointOperation.__table__,
            # Parent creation records every queued step transactionally.
            ModuleOperationStep.__table__,
        )])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    device = Device(id=uuid4(), device_identifier="READ-01", display_name="Read only device")
    owner = ServiceClient(id=uuid4(), client_identifier="endpoint-console-internal", display_name="Console")
    definition = ModuleDefinition(id=uuid4(), module_key="system.adapters", display_name="Adapters")
    recipe = {
        "schema_version": "endpoint_recipe_module_v1", "module_key": definition.module_key,
        "supported_platforms": ["linux_amd64"],
        "inputs": [{"name": "target", "value_type": "string"}],
        "steps": [
            {"step_id": "dns", "capability": "dns.resolve", "parameters": {
                "target": {"kind": "input", "name": "target"},
                "family": {"kind": "literal", "value": "any"},
            }},
            {"step_id": "adapters", "capability": "adapter.list", "parameters": {}},
        ],
    }
    version = ModuleVersion(id=uuid4(), module_definition_id=definition.id, version="1.0.0", recipe=recipe, state="published")
    newer_version = ModuleVersion(id=uuid4(), module_definition_id=definition.id, version="1.1.0", recipe=recipe, state="published")
    async with sessions() as session:
        session.add_all([device, owner, definition, version, newer_version]); await session.commit()
    settings = Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused", public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"modules-test-device-pepper", service_token_pepper=b"modules-test-service-pepper",
        session_secret=b"modules-test-session-secret", allowed_agent_cidrs=(), allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"), endpoint_module_platform_enabled=True,
        endpoint_module_execution_enabled=True, endpoint_read_only_primitives_enabled=True,
        endpoint_network_primitives_enabled=True,
        endpoint_network_probe_allowed_suffixes=(".example.test",),
        endpoint_operations_api_enabled=True,
    )
    app = create_app(settings, session_provider=sessions)
    await app.state.gateway_connection_registry.register(GatewayConnection(
        device.id, uuid4(), object(), agent_version="3.2.63", platform="linux_amd64",
        effective_capabilities=frozenset({"dns.resolve", "adapter.list"}),
    ))
    user_id = uuid4()
    app.dependency_overrides[require_admin] = lambda: AdminPrincipal(
        user=AdminUser(id=user_id, username="operator", password_digest="unused", scopes=[], disabled_at=None),
        session=AdminSession(id=uuid4(), admin_user_id=user_id, session_digest="unused", expires_at=datetime.now(UTC) + timedelta(hours=1), revoked_at=None),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        catalog_first = await client.get("/api/admin/console/modules?limit=1")
        catalog_second = await client.get("/api/admin/console/modules?limit=1&offset=1")
        available = await client.get(f"/api/admin/console/devices/{device.id}/modules")
        first_page = await client.get(f"/api/admin/console/devices/{device.id}/modules?limit=1")
        second_page = await client.get(f"/api/admin/console/devices/{device.id}/modules?limit=1&offset=1")
        run = await client.post(f"/api/admin/console/devices/{device.id}/module-operations", headers={"Idempotency-Key": "console-read-only-0001"}, json={
            "schema_version": "endpoint_module_operation_create_v1", "module_key": definition.module_key,
            "version": "1.0.0", "inputs": {"target": "api.example.test"},
        })
        operation_detail = await client.get(f"/api/admin/operations/{run.json()['data']['operation_id']}")
    await engine.dispose()
    assert catalog_first.json()["total"] == catalog_second.json()["total"] == 2
    assert {
        catalog_first.json()["data"][0]["versions"][0]["version"],
        catalog_second.json()["data"][0]["versions"][0]["version"],
    } == {"1.0.0", "1.1.0"}
    assert available.status_code == 200 and available.json()["data"][0]["compatible"] is True
    assert first_page.json()["total"] == second_page.json()["total"] == 2
    assert {first_page.json()["data"][0]["version"], second_page.json()["data"][0]["version"]} == {"1.0.0", "1.1.0"}
    assert run.status_code == 201 and run.json()["data"]["status"] == "queued"
    assert operation_detail.status_code == 200
    assert operation_detail.json()["operation"] is None
    assert [step["capability"] for step in operation_detail.json()["module_detail"]["steps"]] == ["dns.resolve", "adapter.list"]
    assert "api.example.test" not in operation_detail.text
    assert "console-read-only-0001" not in operation_detail.text
