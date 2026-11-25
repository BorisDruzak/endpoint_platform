from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from endpoint_contracts import AgentHelloV1
from endpoint_server.db.models import Device, DeviceCredential
from endpoint_server.gateway.ws_routes import (
    GatewayHandshakeRejected,
    authenticate_gateway_websocket,
    validate_agent_hello,
)
from endpoint_server.main import create_app

from .conftest import FakeGatewaySocket, agent_hello, gateway_settings, seed_device


@pytest.mark.asyncio
async def test_valid_device_bearer_authenticates_from_trusted_tls_proxy(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    socket = FakeGatewaySocket(session_provider)
    statements = []

    def observe(_connection, _cursor, statement, *_):
        statements.append(statement)

    engine = session_provider.kw["bind"].sync_engine
    event.listen(engine, "before_cursor_execute", observe)
    try:
        authenticated = await authenticate_gateway_websocket(socket)
    finally:
        event.remove(engine, "before_cursor_execute", observe)

    assert authenticated.principal.device.id == device.id
    assert str(authenticated.source_address) == "192.168.101.20"
    assert len(statements) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("with_active_device", [False, True])
async def test_retired_device_bearer_remains_ineligible(session_provider, with_active_device):
    active = await seed_device(session_provider)
    retired = await seed_device(session_provider, token=uuid4().hex) if with_active_device else active
    async with session_provider() as session:
        device = await session.get(Device, retired.id)
        device.retired_at = datetime.now(UTC)
        if with_active_device:
            current = await session.scalar(select(DeviceCredential).where(DeviceCredential.device_id == active.id))
            duplicate = await session.scalar(select(DeviceCredential).where(DeviceCredential.device_id == retired.id))
            duplicate.pending_token_digest = current.token_digest
            duplicate.rotation_overlap_expires_at = datetime.now(UTC) + timedelta(minutes=5)
        await session.commit()

    with pytest.raises(GatewayHandshakeRejected) as rejected:
        await authenticate_gateway_websocket(FakeGatewaySocket(session_provider))

    assert rejected.value.close_code == 4401


@pytest.mark.asyncio
async def test_revoked_device_bearer_is_rejected(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    await seed_device(session_provider, revoked=True)

    with pytest.raises(GatewayHandshakeRejected) as rejected:
        await authenticate_gateway_websocket(FakeGatewaySocket(session_provider))

    assert rejected.value.close_code == 4401


@pytest.mark.asyncio
async def test_authenticated_token_cannot_claim_a_different_device(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    authenticated = await authenticate_gateway_websocket(
        FakeGatewaySocket(session_provider)
    )
    hello = AgentHelloV1.model_validate(agent_hello(uuid4()))

    with pytest.raises(GatewayHandshakeRejected) as rejected:
        validate_agent_hello(authenticated, hello)

    assert rejected.value.close_code == 4403
    assert authenticated.principal.device.id == device.id


@pytest.mark.asyncio
async def test_source_outside_approved_agent_cidr_is_rejected(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    await seed_device(session_provider)
    socket = FakeGatewaySocket(session_provider, source="198.51.100.25")

    with pytest.raises(GatewayHandshakeRejected) as rejected:
        await authenticate_gateway_websocket(socket)

    assert rejected.value.close_code == 4401


@pytest.mark.asyncio
async def test_trusted_proxy_without_https_metadata_is_rejected(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    await seed_device(session_provider)
    socket = FakeGatewaySocket(session_provider, forwarded_proto=None)

    with pytest.raises(GatewayHandshakeRejected) as rejected:
        await authenticate_gateway_websocket(socket)

    assert rejected.value.close_code == 4401


@pytest.mark.asyncio
async def test_raw_bearer_never_enters_gateway_logs(
    session_provider: async_sessionmaker[AsyncSession],
    caplog: pytest.LogCaptureFixture,
) -> None:
    await seed_device(session_provider)
    raw_token = "raw-gateway-token-that-must-not-be-logged"
    caplog.set_level(logging.DEBUG)

    with pytest.raises(GatewayHandshakeRejected):
        await authenticate_gateway_websocket(
            FakeGatewaySocket(session_provider, token=raw_token)
        )

    assert raw_token not in caplog.text


def test_wss_route_is_exact_and_https_pull_routes_remain_enabled(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    app = create_app(gateway_settings(), session_provider)
    paths = {route.path for route in app.routes}

    assert "/agent/v1/connect" in paths
    assert "/agent/v1/gateway/commands/next" in paths
    assert not any("inventory" in path and path.startswith("/agent/v1/") for path in paths)
