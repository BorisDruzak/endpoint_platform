from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
import ipaddress
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_server.config import Settings
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.db.models import AuditEvent, Device, ServiceClient, ServiceCredential
from endpoint_server.main import create_app
from endpoint_server.auth.scopes import ServicePrincipal


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:", public_base_url="https://endpoint.sosnadmin.local",
        session_secret=b"session-secret", service_token_pepper=b"service-pepper", device_token_pepper=b"device-pepper",
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),), artifact_root=Path("artifacts"),
    )


@pytest_asyncio.fixture
async def session_provider() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (Device.__table__, AuditEvent.__table__, ContextCollection.__table__, ContextSnapshot.__table__, ContextCurrent.__table__)
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Device.metadata.create_all(sync, tables=tables))
    provider = async_sessionmaker(engine, expire_on_commit=False)
    yield provider
    await engine.dispose()


def _principal(scopes: list[str]) -> ServicePrincipal:
    client = ServiceClient(id=uuid4(), client_identifier="web-ovpn", display_name="web_ovpn", disabled_at=None)
    credential = ServiceCredential(
        id=uuid4(), service_client_id=client.id, credential_identifier="a" * 32, token_prefix="svc_" + "a" * 32,
        secret_digest="digest", scopes=scopes, expires_at=None, revoked_at=None,
    )
    return ServicePrincipal(client=client, credential=credential)


def _install_principals(monkeypatch: pytest.MonkeyPatch, principals: dict[str, ServicePrincipal]) -> None:
    import endpoint_server.auth.scopes as scopes_module

    async def load(_: AsyncSession, token: str, __: bytes) -> ServicePrincipal | None:
        return principals.get(token)

    monkeypatch.setattr(scopes_module, "_load_service_principal", load)


@pytest.mark.asyncio
async def test_service_context_read_projection_excludes_raw_payload_and_diagnostics(session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    async with session_provider() as session:
        token = "read-token"
        device = Device(id=uuid4(), device_identifier="context-device", display_name="Context device", retired_at=None)
        collection = ContextCollection(id=uuid4(), device_id=device.id, profile="baseline_v1", requested_by="svc", idempotency_key="seed", status="completed", requested_at=datetime.now(UTC), raw_result_payload={"token": "secret"})
        snapshot = ContextSnapshot(id=uuid4(), collection_id=collection.id, device_id=device.id, profile="baseline_v1", collected_at=datetime.now(UTC), semantic_hash="b" * 64, raw_payload={"result_items": [{"traceback": "raw diagnostic"}]}, normalized_projection={"schema_version": "device_context_v1", "profile": "baseline_v1", "warnings": [], "sections": {"system": {"platform": "linux"}}})
        current = ContextCurrent(id=uuid4(), device_id=device.id, profile="baseline_v1", snapshot_id=snapshot.id, updated_at=datetime.now(UTC))
        session.add_all((device, collection, snapshot, current))
        await session.commit()
    _install_principals(monkeypatch, {token: _principal(["context.read"])})
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.get(f"/api/v1/devices/{device.id}/context", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert "raw_payload" not in response.text
    assert "raw diagnostic" not in response.text
    assert "secret" not in response.text
    assert "token" not in response.text


@pytest.mark.asyncio
async def test_device_listing_requires_devices_read_not_context_read(session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    async with session_provider() as session:
        device = Device(id=uuid4(), device_identifier="listed-device", display_name="Listed", retired_at=None)
        session.add(device)
        await session.commit()
    _install_principals(monkeypatch, {
        "device-reader": _principal(["devices.read"]),
        "context-reader": _principal(["context.read"]),
    })
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        allowed = await client.get("/api/v1/devices", headers={"Authorization": "Bearer device-reader"})
        denied = await client.get("/api/v1/devices", headers={"Authorization": "Bearer context-reader"})
    assert allowed.status_code == 200
    assert allowed.json()["data"] == [{"id": str(device.id), "device_identifier": "listed-device", "display_name": "Listed", "retired_at": None}]
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_collection_request_requires_exact_scope_idempotency_and_audit(session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    async with session_provider() as session:
        denied_token = "denied-token"
        allowed_token = "allowed-token"
        device = Device(id=uuid4(), device_identifier="collect-device", display_name="Collect device", retired_at=None)
        session.add(device)
        await session.commit()
    _install_principals(monkeypatch, {
        denied_token: _principal(["context.read"]),
        allowed_token: _principal(["context.collect"]),
    })
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        denied = await client.post(f"/api/v1/devices/{device.id}/context/collections", json={"profile": "baseline_v1"}, headers={"Authorization": f"Bearer {denied_token}", "Idempotency-Key": "request-001"})
        missing_key = await client.post(f"/api/v1/devices/{device.id}/context/collections", json={"profile": "baseline_v1"}, headers={"Authorization": f"Bearer {allowed_token}"})
        created = await client.post(f"/api/v1/devices/{device.id}/context/collections", json={"profile": "baseline_v1"}, headers={"Authorization": f"Bearer {allowed_token}", "Idempotency-Key": "request-001", "X-Request-ID": "Bearer raw secret"})
        replay = await client.post(f"/api/v1/devices/{device.id}/context/collections", json={"profile": "baseline_v1"}, headers={"Authorization": f"Bearer {allowed_token}", "Idempotency-Key": "request-001"})
    assert denied.status_code == 403
    assert missing_key.status_code == 422
    assert created.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["data"]["id"] == created.json()["data"]["id"]
    async with session_provider() as session:
        events = (await session.scalars(select(AuditEvent))).all()
    assert len(events) == 1
    assert events[0].action == "context.collection_requested"
    assert "raw secret" not in str(events[0].details)
