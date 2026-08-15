"""Acceptance tests for Endpoint-owned runtime diagnostic target state."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
import ipaddress
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_server.config import Settings
from endpoint_server.auth.scopes import ServicePrincipal
from endpoint_server.db.models import (
    AuditEvent,
    Device,
    DeviceCredential,
    DeviceInstance,
    DeviceSession,
    ServiceClient,
    ServiceCredential,
)
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.main import create_app


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"device-pepper",
        service_token_pepper=b"service-pepper",
        session_secret=b"runtime-session-secret",
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        artifact_root=Path("artifacts"),
    )


def _as_utc(value: datetime) -> datetime:
    """Normalize SQLite fixture timestamps without altering production UTC values."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@pytest_asyncio.fixture
async def session_provider() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        Device.__table__,
        DeviceCredential.__table__,
        DeviceInstance.__table__,
        DeviceSession.__table__,
        AuditEvent.__table__,
    )
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(sync, tables=tables)
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _device_with_bearer(
    session_provider: async_sessionmaker[AsyncSession], token: str
) -> Device:
    device = Device(id=uuid4(), device_identifier="runtime-device", display_name="Runtime", retired_at=None)
    async with session_provider() as session:
        session.add_all(
            (
                device,
                DeviceCredential(
                    id=uuid4(),
                    device_id=device.id,
                    credential_identifier="runtime-credential",
                    token_digest=device_token_digest(token, b"device-pepper"),
                    pending_token_digest=None,
                    rotation_overlap_expires_at=None,
                    expires_at=None,
                    revoked_at=None,
                ),
            )
        )
        await session.commit()
    return device


def _principal(*, client_identifier: str, scopes: list[str]) -> ServicePrincipal:
    client = ServiceClient(
        id=uuid4(),
        client_identifier=client_identifier,
        display_name=client_identifier,
        disabled_at=None,
    )
    credential = ServiceCredential(
        id=uuid4(),
        service_client_id=client.id,
        credential_identifier="a" * 32,
        token_prefix="svc_" + "a" * 32,
        secret_digest="digest",
        scopes=scopes,
        expires_at=None,
        revoked_at=None,
    )
    return ServicePrincipal(client=client, credential=credential)


def _install_principals(
    monkeypatch: pytest.MonkeyPatch, principals: dict[str, ServicePrincipal]
) -> None:
    import endpoint_server.auth.scopes as scopes_module

    async def load(_: AsyncSession, token: str, __: bytes) -> ServicePrincipal | None:
        return principals.get(token)

    monkeypatch.setattr(scopes_module, "_load_service_principal", load)


async def _store_runtime_state(
    session_provider: async_sessionmaker[AsyncSession],
    device: Device,
    *,
    seen_at: datetime | None,
    handshake_at: datetime | None,
    expires_at: datetime,
    agent_version: str = "3.2.11",
) -> None:
    async with session_provider() as session:
        instance = DeviceInstance(
            id=uuid4(),
            device_id=device.id,
            instance_identifier="runtime-gateway",
            agent_version=agent_version,
            last_seen_at=seen_at,
        )
        session.add(instance)
        await session.flush()
        session.add(
            DeviceSession(
                id=uuid4(),
                device_id=device.id,
                device_instance_id=instance.id,
                session_identifier=f"runtime-{uuid4().hex}",
                expires_at=expires_at,
                last_handshake_at=handshake_at,
                closed_at=None,
            )
        )
        await session.commit()


@pytest.mark.asyncio
async def test_heartbeat_persists_server_observed_session_and_ignores_reported_time(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Presence must be established by server time, never by a client clock claim."""
    token = "runtime-device-token"
    device = await _device_with_bearer(session_provider, token)
    app = create_app(_settings(), session_provider)

    before = datetime.now(UTC)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/agent/v1/runtime/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "schema_version": "agent_heartbeat_v1",
                "device_id": str(device.id),
                "platform": "linux",
                "agent_version": "3.2.11",
                "reported_at": "2000-01-01T00:00:00Z",
            },
        )

    assert response.status_code == 204
    async with session_provider() as session:
        instance = await session.scalar(select(DeviceInstance).where(DeviceInstance.device_id == device.id))
        runtime_session = await session.scalar(select(DeviceSession).where(DeviceSession.device_id == device.id))
    assert instance is not None
    assert runtime_session is not None
    assert instance.agent_version == "3.2.11"
    assert instance.last_seen_at is not None and _as_utc(instance.last_seen_at) >= before
    assert runtime_session.last_handshake_at is not None
    assert _as_utc(runtime_session.last_handshake_at) >= before
    assert _as_utc(runtime_session.expires_at) - _as_utc(runtime_session.last_handshake_at) == timedelta(seconds=90)


@pytest.mark.asyncio
async def test_heartbeat_rejects_body_device_other_than_bearer_device(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A bearer must never be able to write runtime state for another device."""
    token = "runtime-device-token"
    await _device_with_bearer(session_provider, token)
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/agent/v1/runtime/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "schema_version": "agent_heartbeat_v1",
                "device_id": str(uuid4()),
                "platform": "linux",
                "agent_version": "3.2.11",
                "reported_at": "2026-08-16T10:00:00Z",
            },
        )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_helpdesk_reads_exact_correlated_online_runtime_projection(
    session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changing identity/scope/schema or field allowlist must break the Helpdesk boundary."""
    device = await _device_with_bearer(session_provider, "runtime-device-token")
    now = datetime.now(UTC)
    await _store_runtime_state(
        session_provider,
        device,
        seen_at=now,
        handshake_at=now,
        expires_at=now + timedelta(seconds=90),
    )
    _install_principals(
        monkeypatch,
        {
            "helpdesk": _principal(
                client_identifier="helpdesk", scopes=["helpdesk.diagnostic_target.read"]
            )
        },
    )
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local"
    ) as client:
        response = await client.get(
            f"/service/v1/runtime/devices/{device.id}",
            headers={"Authorization": "Bearer helpdesk", "X-Correlation-ID": "diag-42"},
        )

    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == "diag-42"
    assert response.json()["schema_version"] == "endpoint_runtime_v1"
    assert response.json()["correlation_id"] == "diag-42"
    assert response.json()["data"] | {"device_ref": str(device.id)} == response.json()["data"]
    assert response.json()["data"] == {
        "device_ref": str(device.id),
        "online": True,
        "connection_state": "online",
        "last_seen_at": response.json()["data"]["last_seen_at"],
        "last_handshake_at": response.json()["data"]["last_handshake_at"],
        "agent_version": "3.2.11",
    }


@pytest.mark.asyncio
async def test_runtime_read_requires_helpdesk_identity_and_exact_scope(
    session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scope-only principal or a Helpdesk principal without scope must be denied."""
    device = await _device_with_bearer(session_provider, "runtime-device-token")
    _install_principals(
        monkeypatch,
        {
            "other": _principal(
                client_identifier="other", scopes=["helpdesk.diagnostic_target.read"]
            ),
            "missing-scope": _principal(client_identifier="helpdesk", scopes=[]),
        },
    )
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local"
    ) as client:
        other = await client.get(
            f"/service/v1/runtime/devices/{device.id}",
            headers={"Authorization": "Bearer other", "X-Correlation-ID": "diag-43"},
        )
        missing_scope = await client.get(
            f"/service/v1/runtime/devices/{device.id}",
            headers={"Authorization": "Bearer missing-scope", "X-Correlation-ID": "diag-44"},
        )
        missing_bearer = await client.get(
            f"/service/v1/runtime/devices/{device.id}",
            headers={"X-Correlation-ID": "diag-45"},
        )

    assert other.status_code == 403
    assert missing_scope.status_code == 403
    assert missing_bearer.status_code == 401


@pytest.mark.asyncio
async def test_helpdesk_gets_only_correlated_404_for_unknown_device(
    session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only an exact absent Endpoint UUID may be represented as diagnostic not-found."""
    _install_principals(
        monkeypatch,
        {
            "helpdesk": _principal(
                client_identifier="helpdesk", scopes=["helpdesk.diagnostic_target.read"]
            )
        },
    )
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local"
    ) as client:
        response = await client.get(
            f"/service/v1/runtime/devices/{uuid4()}",
            headers={"Authorization": "Bearer helpdesk", "X-Correlation-ID": "diag-404"},
        )

    assert response.status_code == 404
    assert response.headers["X-Correlation-ID"] == "diag-404"
    assert response.json() == {
        "correlation_id": "diag-404",
        "data": {"status": "not_found", "code": "endpoint_device_not_found"},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("expired", (False, True))
async def test_absent_or_expired_heartbeat_is_offline(
    session_provider: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    expired: bool,
) -> None:
    """No durable live session must never be projected as online."""
    device = await _device_with_bearer(session_provider, "runtime-device-token")
    if expired:
        stale = datetime.now(UTC) - timedelta(seconds=91)
        await _store_runtime_state(
            session_provider, device, seen_at=stale, handshake_at=stale, expires_at=stale
        )
    _install_principals(
        monkeypatch,
        {"helpdesk": _principal(client_identifier="helpdesk", scopes=["helpdesk.diagnostic_target.read"])},
    )
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.get(
            f"/service/v1/runtime/devices/{device.id}",
            headers={"Authorization": "Bearer helpdesk", "X-Correlation-ID": "diag-offline"},
        )

    assert response.status_code == 200
    assert response.json()["data"]["online"] is False
    assert response.json()["data"]["connection_state"] == "offline"


@pytest.mark.asyncio
async def test_invalid_correlation_and_uuid_are_not_not_found(
    session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed routing/correlation inputs must fail closed rather than enumerate as 404."""
    _install_principals(
        monkeypatch,
        {"helpdesk": _principal(client_identifier="helpdesk", scopes=["helpdesk.diagnostic_target.read"])},
    )
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        invalid_correlation = await client.get(
            f"/service/v1/runtime/devices/{uuid4()}",
            headers={"Authorization": "Bearer helpdesk", "X-Correlation-ID": "bad\tcorrelation"},
        )
        invalid_uuid = await client.get(
            "/service/v1/runtime/devices/not-a-uuid",
            headers={"Authorization": "Bearer helpdesk", "X-Correlation-ID": "diag-invalid"},
        )

    assert invalid_correlation.status_code == 422
    assert invalid_uuid.status_code == 422
    assert invalid_correlation.json()["detail"] != "endpoint_device_not_found"
    assert invalid_uuid.json()["detail"] != "endpoint_device_not_found"


@pytest.mark.asyncio
async def test_runtime_api_and_audit_exclude_device_credentials_and_network_identifiers(
    session_provider: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A projection/audit widening must never disclose stored identity or bearer material."""
    token = "raw-device-token-marker"
    device = await _device_with_bearer(session_provider, token)
    device.device_identifier = "install-secret-marker-mac-aabbccddeeff-ip-192.0.2.10"
    async with session_provider() as session:
        persisted = await session.get(Device, device.id)
        assert persisted is not None
        persisted.device_identifier = device.device_identifier
        await session.commit()
    _install_principals(
        monkeypatch,
        {"helpdesk": _principal(client_identifier="helpdesk", scopes=["helpdesk.diagnostic_target.read"])},
    )
    app = create_app(_settings(), session_provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        response = await client.get(
            f"/service/v1/runtime/devices/{device.id}",
            headers={"Authorization": "Bearer helpdesk", "X-Correlation-ID": "diag-redacted"},
        )
    async with session_provider() as session:
        audit = await session.scalar(select(AuditEvent).order_by(AuditEvent.created_at.desc()))

    assert response.status_code == 200
    assert audit is not None
    exposed = response.text + str(audit.details)
    for marker in (token, "install-secret-marker", "aabbccddeeff", "192.0.2.10"):
        assert marker not in exposed
