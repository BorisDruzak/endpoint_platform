"""Published discovery must never select a draft or bypass device/scope gates."""
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth import scopes
from endpoint_server.config import Settings
from endpoint_server.db.models import Device, ModuleDefinition, ModuleVersion, ServiceClient, ServiceCredential
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_server.main import create_app


@pytest_asyncio.fixture
async def catalog_app(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: [table.create(sync) for table in (
            Device.__table__, ModuleDefinition.__table__, ModuleVersion.__table__,
        )])
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.example.test", device_token_pepper=b"test-device",
        service_token_pepper=b"test-service", session_secret=b"test-session",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(), artifact_root=Path("artifacts"),
        endpoint_module_platform_enabled=True, endpoint_network_primitives_enabled=True,
        endpoint_network_probe_allowed_suffixes=(".example.test",))
    app = create_app(settings, session_provider=sessions)
    credential = ServiceCredential(scopes=["devices.read", "modules.read"])
    principal = scopes.ServicePrincipal(client=ServiceClient(), credential=credential)
    # Isolate the external credential lookup; the actual scope dependencies still run.
    async def load_principal(*args):
        return principal
    monkeypatch.setattr(scopes, "_load_service_principal", load_principal)
    device = Device(id=uuid4(), device_identifier="catalog-test", display_name="Catalog test")
    definition = ModuleDefinition(id=uuid4(), module_key="network.test", display_name="DNS test")
    recipe = {"schema_version": "endpoint_recipe_module_v1", "module_key": "network.test",
        "supported_platforms": ["linux_amd64"], "inputs": [{"name": "target", "value_type": "string"}],
        "steps": [{"step_id": "dns", "capability": "dns.resolve", "parameters": {
            "target": {"kind": "input", "name": "target"},
            "family": {"kind": "literal", "value": "any"}}}]}
    now = datetime.now(UTC)
    async with sessions() as session:
        session.add_all([device, definition])
        for index, (version, state) in enumerate([
            ("1.9.0", "published"), ("1.10.0", "published"), ("2.0.0", "draft"),
            ("3.0.0", "validated"), ("4.0.0", "revoked")]):
            session.add(ModuleVersion(id=uuid4(), module_definition_id=definition.id,
                version=version, state=state, recipe=recipe, created_at=now + timedelta(seconds=index)))
        await session.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.example.test",
        headers={"Authorization": "Bearer test-only", "X-Correlation-ID": "catalog-test"}) as client:
        yield app, client, device, credential, sessions
    await engine.dispose()


@pytest.mark.asyncio
async def test_draft_does_not_hide_published_version(catalog_app):
    app, client, device, _, _ = catalog_app
    path = f"/api/v1/devices/{device.id}/modules"
    response = await client.get(path, params={"limit": 1})
    assert response.status_code == 200
    page = response.json()
    assert page["schema_version"] == "endpoint_device_modules_v1"
    assert page["device_id"] == str(device.id)
    assert page["items"][0]["version"] == "1.9.0"  # creation order, not lexical SemVer
    assert page["items"][0]["availability"] == "unavailable"
    assert page["items"][0]["reason_code"] == "device_offline"
    assert response.headers["X-Correlation-ID"] == "catalog-test"
    second = (await client.get(path, params={"limit": 1, "cursor": page["next_cursor"]})).json()
    assert second["items"][0]["version"] == "1.10.0"
    assert second["next_cursor"] is None
    assert {item["state"] for item in page["items"] + second["items"]} == {"published"}
    await app.state.gateway_connection_registry.register(GatewayConnection(
        device.id, uuid4(), object(), agent_version="3.2.82", platform="linux_amd64",
        effective_capabilities=frozenset({"dns.resolve"})))
    online = (await client.get(path)).json()
    assert all(item["availability"] == "available" and item["reason_code"] is None for item in online["items"])


@pytest.mark.asyncio
async def test_device_modules_page_auth_and_bounds(catalog_app):
    _, client, device, credential, sessions = catalog_app
    path = f"/api/v1/devices/{device.id}/modules"
    for limit in (0, 101):
        assert (await client.get(path, params={"limit": limit})).status_code == 422
    assert (await client.get(path, params={"cursor": "invalid"})).status_code == 400
    for granted in (["devices.read"], ["modules.read"]):
        credential.scopes = granted
        assert (await client.get(path)).status_code == 403
    credential.scopes = ["devices.read", "modules.read"]
    assert (await client.get(f"/api/v1/devices/{uuid4()}/modules")).status_code == 404
    async with sessions() as session:
        record = await session.get(Device, device.id)
        record.retired_at = datetime.now(UTC)
        await session.commit()
    assert (await client.get(path)).status_code == 404


@pytest.mark.asyncio
async def test_missing_agent_facts_are_unknown_and_invalid_recipe_is_visible(catalog_app):
    app, client, device, _, sessions = catalog_app
    await app.state.gateway_connection_registry.register(GatewayConnection(device.id, uuid4(), object()))
    path = f"/api/v1/devices/{device.id}/modules"
    response = await client.get(path)
    assert response.status_code == 200
    assert {item["availability"] for item in response.json()["items"]} == {"unknown"}
    async with sessions() as session:
        from sqlalchemy import select
        version = await session.scalar(select(ModuleVersion).where(ModuleVersion.version == "1.9.0"))
        version.recipe = {"secret": "must-not-project"}
        await session.commit()
    invalid = (await client.get(path)).json()["items"][0]
    assert invalid["reason_code"] == "invalid_recipe"
    assert invalid["recipe"] is None
    assert "secret" not in str(invalid)


@pytest.mark.asyncio
async def test_invalid_literal_recipe_cannot_look_available(catalog_app):
    app, client, device, _, sessions = catalog_app
    await app.state.gateway_connection_registry.register(GatewayConnection(
        device.id, uuid4(), object(), agent_version="3.2.82", platform="linux_amd64",
        effective_capabilities=frozenset({"dns.resolve"})))
    from sqlalchemy import select
    async with sessions() as session:
        version = await session.scalar(select(ModuleVersion).where(ModuleVersion.version == "1.9.0"))
        recipe = dict(version.recipe)
        recipe["steps"] = [{"step_id": "dns", "capability": "dns.resolve", "parameters": {
            "target": {"kind": "input", "name": "target"}, "family": {"kind": "literal", "value": "invalid"}}}]
        version.recipe = recipe
        await session.commit()
    item = (await client.get(f"/api/v1/devices/{device.id}/modules")).json()["items"][0]
    assert item["reason_code"] == "invalid_recipe"
    assert item["recipe"] is None


@pytest.mark.asyncio
async def test_cursor_is_bound_to_device_and_tampering_is_rejected(catalog_app):
    _, client, device, _, sessions = catalog_app
    path = f"/api/v1/devices/{device.id}/modules"
    cursor = (await client.get(path, params={"limit": 1})).json()["next_cursor"]
    other = Device(id=uuid4(), device_identifier="other-catalog", display_name="Other")
    async with sessions() as session:
        session.add(other)
        await session.commit()
    assert (await client.get(f"/api/v1/devices/{other.id}/modules", params={"cursor": cursor})).status_code == 400
    assert (await client.get(path, params={"cursor": "A" + cursor[1:]})).status_code == 400
    invalid_header = await client.get(path, headers={"X-Correlation-ID": "invalid value"})
    assert invalid_header.status_code == 422
    assert "X-Correlation-ID" not in invalid_header.headers
