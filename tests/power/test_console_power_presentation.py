"""Console timestamps remain separate and respect activity policy gating."""

from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.auth.admin_sessions import require_admin
from endpoint_server.config import Settings
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.db.models import DeviceInstance, DeviceSession
from endpoint_server.main import create_app

from .test_power_provider import NOW
from .test_power_provider import db as db  # noqa: PLC0414 - re-export pytest fixture


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("has_observation", [False, True])
async def test_detail_activity_observation_timestamp_is_policy_gated(db, enabled, has_observation):
    async with db[0].kw["bind"].begin() as connection:
        await connection.run_sync(
            lambda sync: [
                table.create(sync)
                for table in (
                    DeviceInstance.__table__,
                    DeviceSession.__table__,
                    ContextSnapshot.__table__,
                    ContextCurrent.__table__,
                )
            ]
        )
    observed = NOW - timedelta(minutes=5) if has_observation else None
    async with db[0]() as session:
        snapshot = ContextSnapshot(
            device_id=db[1],
            collection_id=uuid4(),
            profile="activity_v1",
            collected_at=NOW,
            raw_payload={},
            normalized_projection={},
        )
        session.add(snapshot)
        await session.flush()
        session.add(
            ContextCurrent(
                device_id=db[1],
                profile="activity_v1",
                snapshot_id=snapshot.id,
                updated_at=NOW,
                last_observed_at=observed,
            )
        )
        await session.commit()
    app = create_app(
        Settings(
            database_url="unused",
            public_base_url="https://endpoint.sosnadmin.local",
            device_token_pepper=b"synthetic",
            service_token_pepper=b"synthetic",
            session_secret=b"synthetic",
            artifact_root=Path("."),
            allowed_admin_cidrs=(),
            allowed_agent_cidrs=(),
            endpoint_policy_enabled=enabled,
        ),
        session_provider=db[0],
    )
    app.dependency_overrides[require_admin] = lambda: object()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        path = f"/api/admin/console/devices/{db[1]}"
        detail = await client.get(path + "?include_power=true")
        assert detail.status_code == 200, detail.text
        header = detail.json()["device"]
        assert "last_activity_observed_at" in header
        assert header["last_activity_observed_at"] == (
            observed.isoformat().replace("+00:00", "Z") if enabled and observed else None
        )
        assert header["last_seen_at"] is None
        assert header["power"]["latest_event"] is None
        assert (await client.get(path)).json()["device"][
            "last_activity_observed_at"
        ] is None
