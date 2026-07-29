"""Device-authenticated update recommendation and outcome HTTP boundary."""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from endpoint_contracts import UpdateBuildManifestV1
from endpoint_server.config import Settings
from endpoint_server.db.models import (
    AuditEvent,
    Device,
    DeviceCredential,
    UpdateBuild,
    UpdateReport,
    UpdateRollout,
    UpdateTarget,
)
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.main import create_app
from endpoint_server.updates.service import create_rollout, register_build


NOW = datetime.now(UTC)
ADMIN_ID = uuid4()


def _settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"device-pepper",
        service_token_pepper=b"service-pepper",
        session_secret=b"request-correlation-secret",
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        artifact_root=Path("artifacts"),
    )


@pytest_asyncio.fixture
async def session_provider() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        Device.__table__,
        DeviceCredential.__table__,
        UpdateBuild.__table__,
        UpdateRollout.__table__,
        UpdateTarget.__table__,
        UpdateReport.__table__,
        AuditEvent.__table__,
    )
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync_connection: Device.metadata.create_all(
                sync_connection,
                tables=tables,
            )
        )
        await connection.execute(text("DROP INDEX uq_update_targets_active_device"))
    provider = async_sessionmaker(engine, expire_on_commit=False)
    yield provider
    await engine.dispose()


async def _seed_device(
    session: AsyncSession,
    *,
    suffix: str,
    token: str,
) -> Device:
    device = Device(
        id=uuid4(),
        device_identifier=f"device-{suffix}",
        display_name=f"Device {suffix}",
        retired_at=None,
    )
    session.add(device)
    session.add(
        DeviceCredential(
            id=uuid4(),
            device_id=device.id,
            credential_identifier=f"credential-{suffix}",
            token_digest=device_token_digest(token, b"device-pepper"),
            pending_token_digest=None,
            rotation_overlap_expires_at=None,
            expires_at=None,
            revoked_at=None,
        )
    )
    await session.flush()
    return device


async def _seed_assignment(
    session: AsyncSession,
    *,
    device: Device,
    build: UpdateBuild | None = None,
    suffix: str,
) -> tuple[UpdateBuild, UpdateTarget]:
    if build is None:
        build = await register_build(
            session,
            UpdateBuildManifestV1.model_validate(
                {
                    "schema_version": "update_build_manifest_v1",
                    "build_identifier": "endpoint-linux-2.0.0",
                    "version": "2.0.0",
                    "platform": "linux_amd64",
                    "channel": "stable",
                    "artifact_url": (
                        "https://releases.example.test/endpoint-linux-2.0.0.tar.gz"
                    ),
                    "artifact_name": "endpoint-linux-2.0.0.tar.gz",
                    "archive_type": "tar.gz",
                    "sha256": "1" * 64,
                    "size": 4096,
                }
            ),
            ADMIN_ID,
            f"register-{suffix}",
            now=NOW,
        )
    rollout = await create_rollout(
        session,
        build.id,
        "canary",
        [device.id],
        f"canary {suffix}",
        ADMIN_ID,
        f"rollout-{suffix}",
        now=NOW,
    )
    target = await session.scalar(
        select(UpdateTarget).where(UpdateTarget.rollout_id == rollout.id)
    )
    assert target is not None
    return build, target


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    )


@pytest.mark.asyncio
async def test_agent_cannot_read_another_devices_recommendation(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Resolving a device from query/body input would disclose another operation."""
    token_a = "device-token-a"
    token_b = "device-token-b"
    async with session_provider() as session:
        device_a = await _seed_device(session, suffix="a", token=token_a)
        device_b = await _seed_device(session, suffix="b", token=token_b)
        build, target_a = await _seed_assignment(
            session,
            device=device_a,
            suffix="a",
        )
        _, target_b = await _seed_assignment(
            session,
            device=device_b,
            build=build,
            suffix="b",
        )
        await session.commit()

    app = create_app(_settings(), session_provider)
    async with _client(app) as client:
        response = await client.get(
            "/agent/v1/updates/recommendation",
            params={
                "platform": "linux_amd64",
                "channel": "stable",
            },
            headers={"Authorization": f"Bearer {token_a}"},
        )
        identity_injection = await client.get(
            "/agent/v1/updates/recommendation",
            params={
                "platform": "linux_amd64",
                "channel": "stable",
                "device_id": str(device_b.id),
            },
            headers={"Authorization": f"Bearer {token_a}"},
        )
        foreign_platform = await client.get(
            "/agent/v1/updates/recommendation",
            params={"platform": "windows_amd64", "channel": "stable"},
            headers={"Authorization": f"Bearer {token_a}"},
        )
        foreign_channel = await client.get(
            "/agent/v1/updates/recommendation",
            params={"platform": "linux_amd64", "channel": "canary"},
            headers={"Authorization": f"Bearer {token_a}"},
        )

    assert response.status_code == 200
    assert response.json()["operation_id"] == target_a.operation_id
    assert target_b.operation_id not in response.text
    assert identity_injection.status_code == 422
    assert str(device_b.id) not in identity_injection.text
    assert foreign_platform.status_code == 204
    assert foreign_platform.content == b""
    assert foreign_channel.status_code == 204
    assert foreign_channel.content == b""


@pytest.mark.asyncio
async def test_inactive_and_unassigned_devices_receive_same_empty_response(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A paused assignment must be indistinguishable from having no assignment."""
    assigned_token = "device-token-paused"
    unassigned_token = "device-token-unassigned"
    async with session_provider() as session:
        assigned = await _seed_device(
            session,
            suffix="paused",
            token=assigned_token,
        )
        await _seed_device(
            session,
            suffix="unassigned",
            token=unassigned_token,
        )
        _, target = await _seed_assignment(
            session,
            device=assigned,
            suffix="paused",
        )
        rollout = await session.get(UpdateRollout, target.rollout_id)
        assert rollout is not None
        rollout.status = "paused"
        rollout.paused_at = NOW
        await session.commit()

    app = create_app(_settings(), session_provider)
    params = {"platform": "linux_amd64", "channel": "stable"}
    async with _client(app) as client:
        paused = await client.get(
            "/agent/v1/updates/recommendation",
            params=params,
            headers={"Authorization": f"Bearer {assigned_token}"},
        )
        unassigned = await client.get(
            "/agent/v1/updates/recommendation",
            params=params,
            headers={"Authorization": f"Bearer {unassigned_token}"},
        )

    assert paused.status_code == unassigned.status_code == 204
    assert paused.content == unassigned.content == b""


@pytest.mark.asyncio
async def test_report_key_is_idempotent_but_payload_conflict_fails(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Accepting a report-key replay with changed payload would rewrite history."""
    token = "device-token-result"
    async with session_provider() as session:
        device = await _seed_device(session, suffix="result", token=token)
        _, target = await _seed_assignment(
            session,
            device=device,
            suffix="result",
        )
        await session.commit()

    app = create_app(_settings(), session_provider)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Request-ID": r"Bearer trace-marker C:\agent\pending_update.json",
    }
    requested = {
        "schema_version": "agent_update_ack_v1",
        "status": "requested",
    }
    scheduled = {
        "schema_version": "agent_update_ack_v1",
        "status": "scheduled",
    }
    report = {
        "schema_version": "agent_update_report_v1",
        "report_key": "launcher-result-1",
        "status": "applied",
        "reported_version": "2.0.0",
        "safe_code": "update.applied",
    }
    operation_url = f"/agent/v1/updates/{target.operation_id}"
    async with _client(app) as client:
        requested_response = await client.post(
            f"{operation_url}/ack",
            json=requested,
            headers=headers,
        )
        scheduled_response = await client.post(
            f"{operation_url}/ack",
            json=scheduled,
            headers=headers,
        )
        first = await client.post(
            f"{operation_url}/reports",
            json=report,
            headers=headers,
        )
        replay = await client.post(
            f"{operation_url}/reports",
            json=report,
            headers=headers,
        )
        conflict = await client.post(
            f"{operation_url}/reports",
            json={**report, "status": "failed"},
            headers=headers,
        )

    assert requested_response.status_code == 204
    assert scheduled_response.status_code == 204
    assert requested_response.content == scheduled_response.content == b""
    assert first.status_code == 200
    assert replay.status_code == 200
    assert first.content == replay.content == b""
    assert conflict.status_code == 409
    assert token not in conflict.text
    assert "pending_update.json" not in conflict.text
    async with session_provider() as session:
        assert await session.scalar(select(func.count()).select_from(UpdateReport)) == 1
        audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action.in_(
                        (
                            "updates.target_acknowledged",
                            "updates.target_reported",
                        )
                    )
                )
            )
        ).all()
    assert len(audits) == 3
    assert all(audit.request_id.startswith("external_") for audit in audits)
    assert all(token not in str(audit.details) for audit in audits)
    assert all("pending_update.json" not in audit.request_id for audit in audits)


@pytest.mark.asyncio
async def test_agent_bodies_are_strict_and_never_reflect_raw_diagnostics(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Accepting identity or traceback extras would cross the safe report boundary."""
    token = "device-token-strict"
    async with session_provider() as session:
        device = await _seed_device(session, suffix="strict", token=token)
        _, target = await _seed_assignment(
            session,
            device=device,
            suffix="strict",
        )
        await session.commit()

    app = create_app(_settings(), session_provider)
    headers = {"Authorization": f"Bearer {token}"}
    raw_path = r"C:\agent\pending_update.json"
    operation_url = f"/agent/v1/updates/{target.operation_id}"
    async with _client(app) as client:
        identity_injection = await client.post(
            f"{operation_url}/ack",
            json={
                "schema_version": "agent_update_ack_v1",
                "status": "requested",
                "device_id": str(uuid4()),
            },
            headers=headers,
        )
        diagnostics_injection = await client.post(
            f"{operation_url}/reports",
            json={
                "schema_version": "agent_update_report_v1",
                "report_key": "strict-report",
                "status": "failed",
                "reported_version": "2.0.0",
                "traceback": f"Bearer raw-secret at {raw_path}",
            },
            headers=headers,
        )

    assert identity_injection.status_code == 422
    assert diagnostics_injection.status_code == 422
    assert str(device.id) not in identity_injection.text
    assert "raw-secret" not in diagnostics_injection.text
    assert "pending_update.json" not in diagnostics_injection.text
    async with session_provider() as session:
        persisted_target = await session.get(UpdateTarget, target.id)
        assert persisted_target is not None
        assert persisted_target.status == "assigned"
        assert await session.scalar(select(UpdateReport.id)) is None


@pytest.mark.asyncio
async def test_foreign_operation_and_invalid_bearer_are_non_enumerating(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Foreign ownership and malformed credentials must not reveal operation state."""
    token_a = "device-token-owner"
    token_b = "device-token-foreign"
    async with session_provider() as session:
        device_a = await _seed_device(session, suffix="owner", token=token_a)
        await _seed_device(session, suffix="foreign", token=token_b)
        _, target = await _seed_assignment(
            session,
            device=device_a,
            suffix="owner",
        )
        await session.commit()

    app = create_app(_settings(), session_provider)
    body = {
        "schema_version": "agent_update_ack_v1",
        "status": "requested",
    }
    url = f"/agent/v1/updates/{target.operation_id}/ack"
    async with _client(app) as client:
        foreign = await client.post(
            url,
            json=body,
            headers={"Authorization": f"Bearer {token_b}"},
        )
        invalid = await client.post(
            url,
            json=body,
            headers={"Authorization": "Bearer raw-secret"},
        )
        malformed_operation = await client.post(
            "/agent/v1/updates/not-an-operation/ack",
            json=body,
            headers={"Authorization": f"Bearer {token_b}"},
        )

    assert foreign.status_code == 404
    assert malformed_operation.status_code == 422
    assert "not-an-operation" not in malformed_operation.text
    assert invalid.status_code == 401
    assert "raw-secret" not in invalid.text
    assert str(UUID(target.operation_id)) not in foreign.text


@pytest.mark.asyncio
async def test_ambiguous_current_and_pending_digest_fails_closed(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A corrupt cross-column digest collision must not choose either device."""
    token = "ambiguous-device-token"
    digest = device_token_digest(token, b"device-pepper")
    async with session_provider() as session:
        first = Device(
            id=uuid4(),
            device_identifier="ambiguous-first",
            display_name="Ambiguous first",
            retired_at=None,
        )
        second = Device(
            id=uuid4(),
            device_identifier="ambiguous-second",
            display_name="Ambiguous second",
            retired_at=None,
        )
        session.add_all(
            (
                first,
                second,
                DeviceCredential(
                    id=uuid4(),
                    device_id=first.id,
                    credential_identifier="ambiguous-current",
                    token_digest=digest,
                    pending_token_digest=None,
                    rotation_overlap_expires_at=None,
                    expires_at=None,
                    revoked_at=None,
                ),
                DeviceCredential(
                    id=uuid4(),
                    device_id=second.id,
                    credential_identifier="ambiguous-pending",
                    token_digest=device_token_digest(
                        "second-current-token",
                        b"device-pepper",
                    ),
                    pending_token_digest=digest,
                    rotation_overlap_expires_at=NOW + timedelta(minutes=10),
                    expires_at=None,
                    revoked_at=None,
                ),
            )
        )
        await session.flush()
        build, _ = await _seed_assignment(
            session,
            device=first,
            suffix="ambiguous-first",
        )
        await _seed_assignment(
            session,
            device=second,
            build=build,
            suffix="ambiguous-second",
        )
        await session.commit()

    app = create_app(_settings(), session_provider)
    async with _client(app) as client:
        response = await client.get(
            "/agent/v1/updates/recommendation",
            params={"platform": "linux_amd64", "channel": "stable"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 401
    assert token not in response.text
