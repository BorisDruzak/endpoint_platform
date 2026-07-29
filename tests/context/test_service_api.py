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
from endpoint_server.db.models import (
    AuditEvent,
    Device,
    DeviceSession,
    ServiceClient,
    ServiceCredential,
)
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
    tables = (
        Device.__table__, DeviceSession.__table__, AuditEvent.__table__,
        ContextCollection.__table__, ContextSnapshot.__table__, ContextCurrent.__table__,
    )
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Device.metadata.create_all(sync, tables=tables))
    provider = async_sessionmaker(engine, expire_on_commit=False)
    yield provider
    await engine.dispose()


def _principal(scopes: list[str], *, client_identifier: str = "web-ovpn") -> ServicePrincipal:
    client = ServiceClient(id=uuid4(), client_identifier=client_identifier, display_name=client_identifier, disabled_at=None)
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


def _normalized_projection(profile: str, collected_at: datetime) -> dict[str, object]:
    sections_by_profile: dict[str, dict[str, object]] = {
        "baseline_v1": {
            "system": {"platform": "linux", "distribution": "ALT", "architecture": "x86_64"},
            "hardware": {"manufacturer": "Acme", "model": "A1", "cpu_model": "CPU", "memory_bytes": 1024},
            "storage": [{"stable_key": "disk:one", "model": "Disk", "size_bytes": 2048}],
            "interfaces": [], "software": [],
        },
        "health_v1": {"resources": {"uptime_seconds": 1, "load_1m": 0.0, "free_bytes": 1}, "services": []},
        "network_v1": {"default_route": {"interface": "eth0", "gateway": "192.0.2.1"}, "interfaces": []},
    }
    return {
        "schema_version": "device_context_v1", "profile": profile,
        "collected_at": collected_at.isoformat(), "warnings": [], "sections": sections_by_profile[profile],
    }


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
async def test_safe_context_routes_exclude_and_reject_diagnostic_collections(session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    """The public service boundary must not expose diagnostic lifecycle metadata."""
    async with session_provider() as session:
        device = Device(id=uuid4(), device_identifier="diagnostic-device", display_name="Diagnostic device", retired_at=None)
        diagnostic = ContextCollection(
            id=uuid4(), device_id=device.id, profile="diagnostic_v1", requested_by="operator",
            idempotency_key="diagnostic-seed", status="completed", requested_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        baseline = ContextCollection(
            id=uuid4(), device_id=device.id, profile="baseline_v1", requested_by="operator",
            idempotency_key="baseline-seed", status="completed", requested_at=datetime.now(UTC),
        )
        session.add_all((device, diagnostic, baseline))
        await session.commit()
    _install_principals(monkeypatch, {"reader": _principal(["context.read"]), "collector": _principal(["context.collect"])})
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        listed = await client.get(f"/api/v1/devices/{device.id}/context", headers={"Authorization": "Bearer reader"})
        read_diagnostic = await client.get(f"/api/v1/context/collections/{diagnostic.id}", headers={"Authorization": "Bearer reader"})
        request_diagnostic = await client.post(
            f"/api/v1/devices/{device.id}/context/collections", json={"profile": "diagnostic_v1"},
            headers={"Authorization": "Bearer collector", "Idempotency-Key": "diagnostic-request"},
        )
    assert listed.status_code == 200
    assert listed.json()["data"]["profiles"] == [{"profile": "baseline_v1", "status": "completed", "last_collected_at": None}]
    assert "diagnostic_v1" not in listed.text
    assert read_diagnostic.status_code == 404
    assert "diagnostic_v1" not in read_diagnostic.text
    assert request_diagnostic.status_code == 422
    assert "diagnostic_v1" not in request_diagnostic.text


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
    assert allowed.json()["data"] == [{"id": str(device.id), "device_identifier": "listed-device", "display_name": "Listed", "retired_at": None, "last_seen_at": None}]
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


@pytest.mark.asyncio
async def test_collection_idempotency_is_scoped_to_the_authenticated_requester(session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    """A shared key cannot replay a different service principal's collection."""
    async with session_provider() as session:
        device = Device(id=uuid4(), device_identifier="principal-device", display_name="Principal device", retired_at=None)
        session.add(device)
        await session.commit()
    _install_principals(monkeypatch, {
        "first": _principal(["context.collect"], client_identifier="web-ovpn-a"),
        "second": _principal(["context.collect"], client_identifier="web-ovpn-b"),
    })
    app = create_app(_settings(), session_provider)
    headers = {"Idempotency-Key": "shared-request-key"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        first = await client.post(f"/api/v1/devices/{device.id}/context/collections", json={"profile": "baseline_v1"}, headers={**headers, "Authorization": "Bearer first"})
        second = await client.post(f"/api/v1/devices/{device.id}/context/collections", json={"profile": "baseline_v1"}, headers={**headers, "Authorization": "Bearer second"})
        replay = await client.post(f"/api/v1/devices/{device.id}/context/collections", json={"profile": "baseline_v1"}, headers={**headers, "Authorization": "Bearer first"})
    assert first.status_code == 201
    assert second.status_code == 201
    assert replay.status_code == 200
    assert first.json()["data"]["id"] != second.json()["data"]["id"]
    assert replay.json()["data"]["id"] == first.json()["data"]["id"]


@pytest.mark.asyncio
async def test_safe_context_snapshots_are_ordered_by_profile(session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    """Safe context lists must stay stable regardless of database insertion order."""
    async with session_provider() as session:
        device = Device(id=uuid4(), device_identifier="ordered-device", display_name="Ordered device", retired_at=None)
        collections = [
            ContextCollection(id=uuid4(), device_id=device.id, profile=profile, requested_by="svc", idempotency_key=f"{profile}-key", status="completed", requested_at=datetime.now(UTC))
            for profile in ("network_v1", "baseline_v1", "health_v1")
        ]
        collected_at = datetime.now(UTC)
        snapshots = [
            ContextSnapshot(id=uuid4(), collection_id=collection.id, device_id=device.id, profile=collection.profile, collected_at=collected_at, semantic_hash=None, raw_payload={}, normalized_projection=_normalized_projection(collection.profile, collected_at))
            for collection in collections
        ]
        session.add_all((device, *collections, *snapshots))
        await session.flush()
        # Insert current pointers in reverse-profile order so unordered SQL leaks into the API.
        for snapshot in snapshots:
            session.add(ContextCurrent(
                id=uuid4(), device_id=device.id, profile=snapshot.profile,
                snapshot_id=snapshot.id, updated_at=datetime.now(UTC),
            ))
            await session.flush()
        await session.commit()
    _install_principals(monkeypatch, {"reader": _principal(["context.read"])})
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.get(f"/api/v1/devices/{device.id}/context", headers={"Authorization": "Bearer reader"})
    assert response.status_code == 200
    assert [item["profile"] for item in response.json()["data"]["snapshots"]] == ["baseline_v1", "health_v1", "network_v1"]


@pytest.mark.asyncio
async def test_baseline_history_is_scoped_bounded_ordered_and_safe(
    session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """History exposes only a bounded newest-first baseline projection for its device."""
    now = datetime.now(UTC)
    async with session_provider() as session:
        device = Device(id=uuid4(), device_identifier="history-device", display_name="History", retired_at=None)
        other = Device(id=uuid4(), device_identifier="other-device", display_name="Other", retired_at=None)
        ids = sorted((uuid4(), uuid4()), key=str)
        oldest = ContextCollection(id=uuid4(), device_id=device.id, profile="baseline_v1", requested_by="svc", idempotency_key="oldest", status="completed", requested_at=now)
        tied_first = ContextCollection(id=uuid4(), device_id=device.id, profile="baseline_v1", requested_by="svc", idempotency_key="tied-first", status="completed", requested_at=now)
        tied_second = ContextCollection(id=uuid4(), device_id=device.id, profile="baseline_v1", requested_by="svc", idempotency_key="tied-second", status="completed", requested_at=now)
        diagnostic = ContextCollection(id=uuid4(), device_id=device.id, profile="diagnostic_v1", requested_by="svc", idempotency_key="diagnostic", status="completed", requested_at=now)
        foreign = ContextCollection(id=uuid4(), device_id=other.id, profile="baseline_v1", requested_by="svc", idempotency_key="foreign", status="completed", requested_at=now)
        snapshots = (
            ContextSnapshot(id=uuid4(), collection_id=oldest.id, device_id=device.id, profile="baseline_v1", collected_at=now.replace(year=2025), semantic_hash="a" * 64, raw_payload={"raw": "secret"}, normalized_projection=_normalized_projection("baseline_v1", now.replace(year=2025))),
            ContextSnapshot(id=ids[0], collection_id=tied_first.id, device_id=device.id, profile="baseline_v1", collected_at=now, semantic_hash="b" * 64, raw_payload={"raw": "secret"}, normalized_projection=_normalized_projection("baseline_v1", now)),
            ContextSnapshot(id=ids[1], collection_id=tied_second.id, device_id=device.id, profile="baseline_v1", collected_at=now, semantic_hash="c" * 64, raw_payload={"raw": "secret"}, normalized_projection=_normalized_projection("baseline_v1", now)),
            ContextSnapshot(id=uuid4(), collection_id=diagnostic.id, device_id=device.id, profile="diagnostic_v1", collected_at=now, semantic_hash=None, raw_payload={"raw": "secret diagnostic"}, normalized_projection={}),
            ContextSnapshot(id=uuid4(), collection_id=foreign.id, device_id=other.id, profile="baseline_v1", collected_at=now, semantic_hash="d" * 64, raw_payload={"raw": "foreign secret"}, normalized_projection=_normalized_projection("baseline_v1", now)),
        )
        session.add_all((device, other, oldest, tied_first, tied_second, diagnostic, foreign, *snapshots))
        await session.commit()
    _install_principals(monkeypatch, {"reader": _principal(["context.read"]), "denied": _principal(["devices.read"])})
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.get(f"/api/v1/devices/{device.id}/context/snapshots", params={"profile": "baseline_v1", "limit": 2}, headers={"Authorization": "Bearer reader"})
        denied = await client.get(f"/api/v1/devices/{device.id}/context/snapshots", headers={"Authorization": "Bearer denied"})
        diagnostic_rejected = await client.get(f"/api/v1/devices/{device.id}/context/snapshots", params={"profile": "diagnostic_v1"}, headers={"Authorization": "Bearer reader"})
        health_rejected = await client.get(f"/api/v1/devices/{device.id}/context/snapshots", params={"profile": "health_v1"}, headers={"Authorization": "Bearer reader"})
        over_limit = await client.get(f"/api/v1/devices/{device.id}/context/snapshots", params={"limit": 101}, headers={"Authorization": "Bearer reader"})
    assert response.status_code == 200
    payload = response.json()["data"]
    assert [item["id"] for item in payload["snapshots"]] == [str(ids[1]), str(ids[0])]
    assert all(item["profile"] == "baseline_v1" for item in payload["snapshots"])
    assert "secret" not in response.text
    assert denied.status_code == 403
    assert diagnostic_rejected.status_code == 422
    assert health_rejected.status_code == 422
    assert over_limit.status_code == 422


@pytest.mark.asyncio
async def test_safe_device_last_seen_comes_from_latest_session_only(
    session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    older = now.replace(year=2025)
    async with session_provider() as session:
        device = Device(id=uuid4(), device_identifier="presence-device", display_name="Presence", retired_at=None)
        other = Device(id=uuid4(), device_identifier="presence-other", display_name="Other", retired_at=None)
        session.add_all((
            device, other,
            DeviceSession(id=uuid4(), device_id=device.id, device_instance_id=None, session_identifier="presence-old", created_at=older, expires_at=now),
            DeviceSession(id=uuid4(), device_id=device.id, device_instance_id=None, session_identifier="presence-new", created_at=now, expires_at=now),
            DeviceSession(id=uuid4(), device_id=other.id, device_instance_id=None, session_identifier="presence-foreign", created_at=now.replace(year=2026), expires_at=now),
        ))
        await session.commit()
    _install_principals(monkeypatch, {"device-reader": _principal(["devices.read"]), "context-reader": _principal(["context.read"])})
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        listed = await client.get("/api/v1/devices", headers={"Authorization": "Bearer device-reader"})
        context = await client.get(f"/api/v1/devices/{device.id}/context", headers={"Authorization": "Bearer context-reader"})
    listed_device = next(item for item in listed.json()["data"] if item["id"] == str(device.id))
    assert datetime.fromisoformat(listed_device["last_seen_at"]).replace(tzinfo=UTC) == now
    assert datetime.fromisoformat(context.json()["data"]["device"]["last_seen_at"]).replace(tzinfo=UTC) == now
    assert "policy" not in context.text.lower()


@pytest.mark.asyncio
async def test_context_comparison_rejects_duplicate_snapshot_id(
    session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with session_provider() as session:
        device = Device(id=uuid4(), device_identifier="compare-device", display_name="Compare", retired_at=None)
        collection = ContextCollection(id=uuid4(), device_id=device.id, profile="baseline_v1", requested_by="svc", idempotency_key="compare", status="completed", requested_at=datetime.now(UTC))
        snapshot = ContextSnapshot(id=uuid4(), collection_id=collection.id, device_id=device.id, profile="baseline_v1", collected_at=datetime.now(UTC), semantic_hash="a" * 64, raw_payload={}, normalized_projection=_normalized_projection("baseline_v1", datetime.now(UTC)))
        session.add_all((device, collection, snapshot))
        await session.commit()
    _install_principals(monkeypatch, {"reader": _principal(["context.read"])})
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.get(f"/api/v1/devices/{device.id}/context/snapshots/compare", params={"before_snapshot_id": str(snapshot.id), "after_snapshot_id": str(snapshot.id)}, headers={"Authorization": "Bearer reader"})
    assert response.status_code == 422
