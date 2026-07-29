"""Authenticated HTTP boundary for immutable update administration."""

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

from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.config import Settings
from endpoint_server.db.models import (
    AdminSession,
    AdminUser,
    AuditEvent,
    Device,
    UpdateBuild,
    UpdateReport,
    UpdateRollout,
    UpdateTarget,
)
from endpoint_server.main import create_app
from endpoint_server.updates.service import (
    create_rollout,
    record_report,
    register_build,
)
from endpoint_contracts import AgentUpdateReportV1, UpdateBuildManifestV1


MANIFEST = {
    "schema_version": "update_build_manifest_v1",
    "build_identifier": "endpoint-linux-2.0.0",
    "version": "2.0.0",
    "platform": "linux_amd64",
    "channel": "stable",
    "artifact_url": "https://releases.example.test/endpoint-linux-2.0.0.tar.gz",
    "artifact_name": "endpoint-linux-2.0.0.tar.gz",
    "archive_type": "tar.gz",
    "sha256": "1" * 64,
    "size": 4096,
    "release_notes": "Endpoint Platform 2.0.0",
}


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


def _principal(scopes: list[str]) -> AdminPrincipal:
    user_id = uuid4()
    return AdminPrincipal(
        user=AdminUser(
            id=user_id,
            username="updates-admin",
            password_digest="$argon2id$test",
            scopes=scopes,
            disabled_at=None,
        ),
        session=AdminSession(
            id=uuid4(),
            admin_user_id=user_id,
            session_digest="session-digest",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            revoked_at=None,
        ),
    )


@pytest_asyncio.fixture
async def session_provider() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        Device.__table__,
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


@pytest.mark.asyncio
async def test_admin_update_scope_is_persisted_not_header_granted(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Trusting a caller scope header would let any signed-in admin grant itself writes."""
    app = create_app(_settings(), session_provider)
    app.dependency_overrides[require_admin] = lambda: _principal([])
    transport = httpx.ASGITransport(
        app=app,
        client=("127.0.0.1", 12345),
    )
    calls = (
        (
            "/api/admin/updates/builds",
            MANIFEST,
        ),
        (
            "/api/admin/updates/rollouts",
            {
                "schema_version": "update_rollout_v1",
                "build_identifier": "missing-build",
                "mode": "canary",
                "device_ids": [str(uuid4())],
                "reason": "scope gate",
            },
        ),
        (f"/api/admin/updates/rollouts/{uuid4()}/activate", None),
        (f"/api/admin/updates/rollouts/{uuid4()}/pause", None),
        (f"/api/admin/updates/rollouts/{uuid4()}/complete", None),
        (
            f"/api/admin/updates/rollouts/{uuid4()}/rollback",
            {
                "schema_version": "update_rollout_v1",
                "build_identifier": "missing-build",
                "mode": "rollback",
                "device_ids": [str(uuid4())],
                "reason": "scope gate",
            },
        ),
    )
    async with httpx.AsyncClient(
        transport=transport,
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        for url, body in calls:
            denied = await client.post(url, json=body)
            forged = await client.post(
                url,
                json=body,
                headers={
                    "X-Scope": "updates:write",
                    "X-Endpoint-Scopes": "updates:write",
                },
            )
            assert denied.status_code == 403, url
            assert forged.status_code == 403, url
    async with session_provider() as session:
        assert await session.scalar(select(UpdateBuild.id)) is None
        assert await session.scalar(select(AuditEvent.id)) is None


@pytest.mark.asyncio
async def test_scoped_admin_registers_build_with_hmac_audit_correlation(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Persisting a raw trace/archive marker would expose request-derived data."""
    app = create_app(_settings(), session_provider)
    principal = _principal(["updates:write"])
    app.dependency_overrides[require_admin] = lambda: principal
    marker = r"Bearer trace-marker C:\agent\pending_update.json"
    transport = httpx.ASGITransport(
        app=app,
        client=("127.0.0.1", 12345),
    )
    async with httpx.AsyncClient(
        transport=transport,
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/admin/updates/builds",
            json=MANIFEST,
            headers={"X-Request-ID": marker},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["build_identifier"] == MANIFEST["build_identifier"]
    assert payload["version"] == "2.0.0"
    assert "password_digest" not in response.text
    async with session_provider() as session:
        build = await session.scalar(select(UpdateBuild))
        audit = await session.scalar(
            select(AuditEvent).where(AuditEvent.action == "updates.build_registered")
        )
    assert build is not None
    assert audit is not None
    assert audit.actor_identifier == str(principal.user.id)
    assert audit.request_id.startswith("external_")
    assert marker not in audit.request_id
    assert marker not in str(audit.details)
    assert "pending_update.json" not in str(audit.details)


@pytest.mark.asyncio
async def test_admin_routes_drive_rollout_lifecycle_and_redact_every_correlation(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Omitting any lifecycle handler or raw-header HMAC would break control-plane use."""
    principal = _principal(["updates:write"])
    device = Device(
        id=uuid4(),
        device_identifier="lifecycle-device",
        display_name="Lifecycle device",
        retired_at=None,
    )
    async with session_provider() as session:
        session.add(device)
        await session.commit()

    app = create_app(_settings(), session_provider)
    app.dependency_overrides[require_admin] = lambda: principal
    marker = r"Bearer lifecycle-trace C:\agent\pending_update.json"
    headers = {"X-Request-ID": marker}
    older_manifest = {
        **MANIFEST,
        "build_identifier": "endpoint-linux-1.9.0",
        "version": "1.9.0",
        "artifact_url": ("https://releases.example.test/endpoint-linux-1.9.0.tar.gz"),
        "artifact_name": "endpoint-linux-1.9.0.tar.gz",
        "sha256": "2" * 64,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        current_response = await client.post(
            "/api/admin/updates/builds",
            json=MANIFEST,
            headers=headers,
        )
        older_response = await client.post(
            "/api/admin/updates/builds",
            json=older_manifest,
            headers=headers,
        )
        rollout_response = await client.post(
            "/api/admin/updates/rollouts",
            json={
                "schema_version": "update_rollout_v1",
                "build_identifier": MANIFEST["build_identifier"],
                "mode": "canary",
                "device_ids": [str(device.id)],
                "reason": "controlled canary",
            },
            headers=headers,
        )
        rollout_id = rollout_response.json()["id"]
        paused = await client.post(
            f"/api/admin/updates/rollouts/{rollout_id}/pause",
            headers=headers,
        )
        activated = await client.post(
            f"/api/admin/updates/rollouts/{rollout_id}/activate",
            headers=headers,
        )
        premature = await client.post(
            f"/api/admin/updates/rollouts/{rollout_id}/complete",
            headers=headers,
        )

        async with session_provider() as session:
            target = await session.scalar(
                select(UpdateTarget).where(UpdateTarget.rollout_id == UUID(rollout_id))
            )
            assert target is not None
            target.status = "failed"
            target.terminal_at = datetime.now(UTC)
            await session.commit()

        completed = await client.post(
            f"/api/admin/updates/rollouts/{rollout_id}/complete",
            headers=headers,
        )
        rollback = await client.post(
            f"/api/admin/updates/rollouts/{rollout_id}/rollback",
            json={
                "schema_version": "update_rollout_v1",
                "build_identifier": older_manifest["build_identifier"],
                "mode": "rollback",
                "device_ids": [str(device.id)],
                "reason": "restore known good",
            },
            headers=headers,
        )

    assert current_response.status_code == 201
    assert older_response.status_code == 201
    assert rollout_response.status_code == 201
    assert paused.status_code == 200
    assert paused.json()["status"] == "paused"
    assert activated.status_code == 200
    assert activated.json()["status"] == "active"
    assert premature.status_code == 409
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert rollback.status_code == 201
    assert rollback.json()["mode"] == "rollback"
    assert rollback.json()["status"] == "active"
    assert "pending_update.json" not in premature.text
    async with session_provider() as session:
        audits = (await session.scalars(select(AuditEvent))).all()
    assert audits
    assert all(audit.request_id.startswith("external_") for audit in audits)
    assert all(marker not in audit.request_id for audit in audits)
    assert all("pending_update.json" not in str(audit.details) for audit in audits)


@pytest.mark.asyncio
async def test_build_replay_is_idempotent_but_manifest_conflict_is_generic(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A changed immutable manifest must conflict without reflecting its URL."""
    app = create_app(_settings(), session_provider)
    app.dependency_overrides[require_admin] = lambda: _principal(["updates:write"])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        first = await client.post("/api/admin/updates/builds", json=MANIFEST)
        replay = await client.post("/api/admin/updates/builds", json=MANIFEST)
        conflict = await client.post(
            "/api/admin/updates/builds",
            json={
                **MANIFEST,
                "artifact_url": (
                    "https://releases.example.test/private/trace-marker.tar.gz"
                ),
                "sha256": "f" * 64,
            },
        )

    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.json()["id"] == first.json()["id"]
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "Update request conflicts with current state"}
    assert "private" not in conflict.text
    assert "trace-marker" not in conflict.text
    async with session_provider() as session:
        assert await session.scalar(select(func.count()).select_from(UpdateBuild)) == 1
        assert (
            await session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "updates.build_registered")
            )
            == 1
        )


@pytest.mark.asyncio
async def test_route_rolls_back_build_when_audit_append_fails(
    session_provider: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A route-level commit must not survive failure of its paired audit event."""
    import endpoint_server.updates.service as service_module

    async def fail_audit(*args: object, **kwargs: object) -> None:
        raise RuntimeError("injected audit failure")

    monkeypatch.setattr(service_module, "append_audit_event", fail_audit)
    app = create_app(_settings(), session_provider)
    app.dependency_overrides[require_admin] = lambda: _principal(["updates:write"])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
            raise_app_exceptions=False,
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post("/api/admin/updates/builds", json=MANIFEST)

    assert response.status_code == 500
    assert "injected audit failure" not in response.text
    async with session_provider() as session:
        assert await session.scalar(select(UpdateBuild.id)) is None
        assert await session.scalar(select(AuditEvent.id)) is None


@pytest.mark.asyncio
async def test_lifecycle_actions_reject_uncontracted_request_bodies(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Ignoring attacker-controlled JSON would leave an unaudited request channel."""
    principal = _principal(["updates:write"])
    async with session_provider() as session:
        device = Device(
            id=uuid4(),
            device_identifier="strict-action-device",
            display_name="Strict action device",
            retired_at=None,
        )
        session.add(device)
        build = await register_build(
            session,
            UpdateBuildManifestV1.model_validate(MANIFEST),
            principal.user.id,
            "strict-action-build",
        )
        rollout = await create_rollout(
            session,
            build.id,
            "canary",
            [device.id],
            "strict action",
            principal.user.id,
            "strict-action-rollout",
        )
        await session.commit()

    app = create_app(_settings(), session_provider)
    app.dependency_overrides[require_admin] = lambda: principal
    marker = r"Bearer action-secret C:\agent\pending_update.json"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            f"/api/admin/updates/rollouts/{rollout.id}/pause",
            json={"traceback": marker},
        )

    assert response.status_code == 422
    assert marker not in response.text
    assert "pending_update.json" not in response.text
    async with session_provider() as session:
        persisted = await session.get(UpdateRollout, rollout.id)
        assert persisted is not None
        assert persisted.status == "active"


@pytest.mark.asyncio
async def test_rollback_endpoint_requires_explicit_rollback_contract_mode(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Calling the rollback URL with a canary body must not bypass mode intent."""
    principal = _principal(["updates:write"])
    async with session_provider() as session:
        device = Device(
            id=uuid4(),
            device_identifier="rollback-mode-device",
            display_name="Rollback mode device",
            retired_at=None,
        )
        session.add(device)
        current = await register_build(
            session,
            UpdateBuildManifestV1.model_validate(MANIFEST),
            principal.user.id,
            "seed-current",
        )
        older_manifest = {
            **MANIFEST,
            "build_identifier": "endpoint-linux-1.9.0",
            "version": "1.9.0",
            "artifact_url": (
                "https://releases.example.test/endpoint-linux-1.9.0.tar.gz"
            ),
            "artifact_name": "endpoint-linux-1.9.0.tar.gz",
            "sha256": "2" * 64,
        }
        await register_build(
            session,
            UpdateBuildManifestV1.model_validate(older_manifest),
            principal.user.id,
            "seed-older",
        )
        trigger = await create_rollout(
            session,
            current.id,
            "canary",
            [device.id],
            "detected regression",
            principal.user.id,
            "seed-trigger",
        )
        target = await session.scalar(
            select(UpdateTarget).where(UpdateTarget.rollout_id == trigger.id)
        )
        assert target is not None
        await record_report(
            session,
            device_id=device.id,
            operation_id=target.operation_id,
            report=AgentUpdateReportV1(
                schema_version="agent_update_report_v1",
                report_key="failed-trigger",
                status="failed",
                reported_version="2.0.0",
                safe_code="update.failed",
            ),
            request_id="seed-report",
        )
        await session.commit()

    app = create_app(_settings(), session_provider)
    app.dependency_overrides[require_admin] = lambda: principal
    body = {
        "schema_version": "update_rollout_v1",
        "build_identifier": "endpoint-linux-1.9.0",
        "mode": "canary",
        "device_ids": [str(device.id)],
        "reason": "restore known good",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            f"/api/admin/updates/rollouts/{trigger.id}/rollback",
            json=body,
        )

    assert response.status_code == 422
    async with session_provider() as session:
        rollback_count = await session.scalar(
            select(func.count())
            .select_from(UpdateRollout)
            .where(UpdateRollout.mode == "rollback")
        )
    assert rollback_count == 0
