"""Dispatch worker-scheduled context work to idle Gateway sockets."""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from uuid import UUID

from endpoint_contracts.gateway_ws import CommandEnvelopeV1
from endpoint_server.db.session import SessionProvider
from endpoint_server.gateway.command_service import CommandService
from endpoint_server.gateway.connection_registry import ConnectionRegistry, GatewayConnection


logger = logging.getLogger(__name__)
_POLL_SECONDS = 1.0
_MAX_CONCURRENT_DELIVERIES = 8
_QUERY_SECONDS = 3.0
_DELIVERY_SECONDS = 5.0
_SEND_SECONDS = 1.0


async def _close_delivery_peer(connection: GatewayConnection, error: Exception) -> None:
    # A committed delivery belongs to this session. Closing it lets the next
    # session replay the same delivery if the send outcome was uncertain.
    connection.ready_for_dispatch.clear()
    logger.warning("Scheduled Gateway send uncertain error=%s session_id=%s",
                   type(error).__name__, connection.session_id)
    try:
        async with asyncio.timeout(_SEND_SECONDS):
            await connection.websocket.close(code=1011)  # type: ignore[attr-defined]
    except Exception as close_error:
        logger.warning("Scheduled Gateway close failed error=%s session_id=%s",
                       type(close_error).__name__, connection.session_id)


async def _deliver(
    service: CommandService, registry: ConnectionRegistry, connection: GatewayConnection,
) -> None:
    if (
        await registry.get(connection.device_id) is not connection
        or not connection.ready_for_dispatch.is_set()
    ):
        return

    async def send(envelope: CommandEnvelopeV1) -> None:
        if await registry.get(connection.device_id) is not connection:
            return
        async with asyncio.timeout(_SEND_SECONDS):
            await connection.send(envelope)

    try:
        async with asyncio.timeout(_DELIVERY_SECONDS):
            await service.deliver_next(
                connection.device_id, connection.session_id, send,
                allowed_capabilities=connection.effective_capabilities,
                agent_platform=connection.platform,
            )
    except Exception as error:
        if await registry.get(connection.device_id) is connection:
            await _close_delivery_peer(connection, error)


async def run_scheduled_dispatch(registry: ConnectionRegistry, provider: SessionProvider) -> None:
    """Scan on its own cadence while a bounded set of workers delivers commands."""
    service = CommandService(provider)
    loop = asyncio.get_running_loop()
    pending: OrderedDict[UUID, GatewayConnection] = OrderedDict()
    running: set[UUID] = set()
    ready = asyncio.Event()

    async def drain() -> None:
        while True:
            await ready.wait()
            while pending:
                device_id, connection = pending.popitem(last=False)
                running.add(device_id)
                if not pending:
                    ready.clear()
                try:
                    await _deliver(service, registry, connection)
                finally:
                    running.remove(device_id)

    async with asyncio.TaskGroup() as workers:
        for _ in range(_MAX_CONCURRENT_DELIVERIES):
            workers.create_task(drain())
        next_scan = loop.time() + _POLL_SECONDS
        while True:
            await asyncio.sleep(max(0.0, next_scan - loop.time()))
            next_scan = loop.time() + _POLL_SECONDS
            owners = {
                connection.device_id: connection for connection in await registry.connected()
                if connection.ready_for_dispatch.is_set() and connection.device_id not in running
            }
            try:
                async with asyncio.timeout(_QUERY_SECONDS):
                    candidates = await service.scheduled_pending_devices(
                        {device_id: owner.effective_capabilities for device_id, owner in owners.items()},
                    )
            except Exception as error:
                logger.warning("Scheduled Gateway scan failed error=%s", type(error).__name__)
                next_scan = loop.time() + _POLL_SECONDS
                continue

            # Refresh from the bounded registry and skip devices that started while
            # PostgreSQL was selecting candidates.
            pending.clear()
            pending.update(
                (device_id, owners[device_id]) for device_id in candidates if device_id not in running
            )
            if pending:
                ready.set()
            else:
                ready.clear()
