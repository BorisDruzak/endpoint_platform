"""Gateway-only delivery and atomic Endpoint Operation lifecycle linkage."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from endpoint_contracts import (
    AgentCommandAckV1,
    AgentHelloV1,
    AgentResultV1,
    DeviceContextDiagnosticV1,
    EndpointOperationCreateV1,
)
from endpoint_contracts.gateway_ws import CommandEnvelopeV1
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import (
    AuditEvent,
    Command,
    CommandDelivery,
    CommandResult,
    EndpointOperation,
    ServiceClient,
)
from endpoint_server.gateway.command_service import (
    CommandService,
    CommandStateRejected,
)
from endpoint_server.gateway.presence_service import GatewayPresence, PresenceService
from endpoint_server.main import create_app
from endpoint_server.operations.projection import project_diagnostic_result
from endpoint_server.operations.service import create_operation_outcome
from endpoint_server.worker import run_worker

from .conftest import (
    VALID_TOKEN,
    agent_hello,
    gateway_settings,
    seed_device,
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def _seed_operation(
    provider: async_sessionmaker[AsyncSession],
    *,
    device_id: UUID,
    reason: str = "Collect bounded diagnostic context",
    now: datetime | None = None,
) -> EndpointOperation:
    requested_at = now or datetime.now(UTC)
    request = EndpointOperationCreateV1.model_validate(
        {
            "schema_version": "endpoint_operation_create_v1",
            "capability": "context.diagnostic.collect",
            "parameters": {"reason": reason},
            "correlation": {
                "schema_version": "endpoint_operation_correlation_v1",
                "source_system": "helpdesk",
                "source_entity_type": "ticket",
                "source_entity_id": "ticket-private-123",
                "request_id": str(uuid4()),
            },
        }
    )
    async with provider() as session:
        client = ServiceClient(
            id=uuid4(),
            client_identifier=f"helpdesk-{uuid4().hex}",
            display_name="Helpdesk",
        )
        session.add(client)
        await session.flush()
        operation, created = await create_operation_outcome(
            session,
            request=request,
            service_client_id=client.id,
            device_id=device_id,
            idempotency_key=f"operation-{uuid4().hex}",
            now=requested_at,
        )
        assert created is True
        await session.commit()
        return operation


async def _open_session(
    provider: async_sessionmaker[AsyncSession],
    *,
    device_id: UUID,
    instance_id: UUID | None = None,
) -> GatewayPresence:
    hello = agent_hello(device_id, instance_id=instance_id)
    hello["capabilities"] = ["context.diagnostic.collect"]
    return await PresenceService(provider).open_session(
        device_id=device_id,
        hello=AgentHelloV1.model_validate(hello),
        source_address="192.168.101.20",
    )


async def _deliver_operation(
    provider: async_sessionmaker[AsyncSession],
    *,
    device_id: UUID,
    session_id: UUID,
) -> CommandEnvelopeV1:
    sent: list[CommandEnvelopeV1] = []
    delivered = await CommandService(provider).deliver_next(
        device_id,
        session_id,
        sent.append,
        allowed_capabilities=frozenset({"context.diagnostic.collect"}),
    )
    assert delivered is True
    assert len(sent) == 1
    return sent[0]


def _diagnostic_result(
    *,
    command_id: UUID,
    device_id: UUID,
    reason: str = "Collect bounded diagnostic context",
    completed_at: datetime | None = None,
    log_excerpt: str | None = "Authorization: Bearer agent-secret",
) -> AgentResultV1:
    observed_at = completed_at or datetime.now(UTC)
    diagnostic = DeviceContextDiagnosticV1.model_validate(
        {
            "schema_version": "device_context_v1",
            "profile": "diagnostic_v1",
            "collected_at": observed_at,
            "warnings": [],
            "sections": {
                "reason": reason,
                "processes": [
                    {"name": "/srv/private/endpoint-agent", "state": "running"}
                ],
                "log_excerpt": log_excerpt,
            },
        }
    )
    return AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command_id,
        device_id=device_id,
        status="succeeded",
        result_items=[diagnostic.model_dump(mode="json")],
        message="diagnostic complete",
        completed_at=observed_at,
    )


@pytest.mark.asyncio
async def test_operation_is_absent_from_http_pull_and_committed_before_wss_send(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Letting HTTP materialize operation work would violate its WSS-only boundary."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    app = create_app(gateway_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.get(
            "/agent/v1/gateway/commands/next",
            headers={
                "Authorization": f"Bearer {VALID_TOKEN}",
                "X-Forwarded-For": "192.168.101.20",
            },
        )

    assert response.status_code == 204
    async with session_provider() as session:
        assert await session.scalar(select(func.count()).select_from(Command)) == 0
        persisted = await session.get(EndpointOperation, operation.id)
        assert persisted is not None
        assert persisted.status == "queued"
        assert persisted.command_id is None

    presence = await _open_session(session_provider, device_id=device.id)
    observed: list[CommandEnvelopeV1] = []

    async def inspect_committed_delivery(envelope: CommandEnvelopeV1) -> None:
        async with session_provider() as session:
            persisted = await session.get(EndpointOperation, operation.id)
            command = await session.get(Command, envelope.payload.command_id)
            delivery = await session.scalar(
                select(CommandDelivery).where(
                    CommandDelivery.command_id == envelope.payload.command_id
                )
            )
        assert persisted is not None and command is not None and delivery is not None
        assert persisted.command_id == command.id
        assert persisted.status == "delivered"
        assert delivery.device_session_id == presence.session_id
        observed.append(envelope)

    assert await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        inspect_committed_delivery,
        allowed_capabilities=frozenset({"context.diagnostic.collect"}),
    )
    payload = observed[0].payload
    serialized = json.dumps(payload.model_dump(mode="json"), sort_keys=True)
    assert payload.capability == "context.diagnostic.collect"
    assert payload.parameters == {"reason": "Collect bounded diagnostic context"}
    assert payload.requested_by_service == "endpoint-platform"
    assert payload.idempotency_key == f"endpoint-operation:{operation.id.hex}"
    assert payload.correlation.request_id == operation.id
    assert payload.correlation.parent_command_id is None
    assert _utc(payload.deadline_at) == _utc(operation.deadline_at)
    assert "helpdesk" not in serialized.lower()
    assert "ticket-private-123" not in serialized


@pytest.mark.asyncio
async def test_legacy_collection_remains_available_to_http_pull(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Filtering linked operations must not remove transitional legacy work."""
    device = await seed_device(session_provider)
    requested_at = datetime.now(UTC)
    async with session_provider() as session:
        session.add(
            ContextCollection(
                id=uuid4(),
                device_id=device.id,
                profile="baseline_v1",
                requested_by="context-scheduler",
                idempotency_key="legacy-http-pull",
                status="requested",
                requested_at=requested_at,
            )
        )
        await session.commit()
    app = create_app(gateway_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.get(
            "/agent/v1/gateway/commands/next",
            headers={
                "Authorization": f"Bearer {VALID_TOKEN}",
                "X-Forwarded-For": "192.168.101.20",
            },
        )

    assert response.status_code == 200
    assert response.json()["capability"] == "context.baseline.collect"
    assert response.json()["requested_by_service"] == "context-scheduler"


@pytest.mark.asyncio
async def test_operation_command_cannot_be_acknowledged_over_http(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Accepting a legacy HTTP ACK would create a second operation control plane."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    acknowledged_at = datetime.now(UTC)
    app = create_app(gateway_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            f"/agent/v1/gateway/commands/{envelope.payload.command_id}/ack",
            headers={
                "Authorization": f"Bearer {VALID_TOKEN}",
                "X-Forwarded-For": "192.168.101.20",
            },
            json={
                "schema_version": "agent_command_ack_v1",
                "command_id": str(envelope.payload.command_id),
                "device_id": str(device.id),
                "status": "acknowledged",
                "acknowledged_at": acknowledged_at.isoformat(),
                "message": None,
            },
        )

    assert response.status_code == 404
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        command = await session.get(Command, envelope.payload.command_id)
    assert persisted is not None and collection is not None and command is not None
    assert persisted.status == command.status == "delivered"
    assert collection.status == "delivered"


@pytest.mark.asyncio
async def test_operation_command_cannot_submit_terminal_result_over_http(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Only the WSS session relation may persist an operation terminal result."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    completed_at = datetime.now(UTC)
    app = create_app(gateway_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            f"/agent/v1/gateway/commands/{envelope.payload.command_id}/results",
            headers={
                "Authorization": f"Bearer {VALID_TOKEN}",
                "X-Forwarded-For": "192.168.101.20",
            },
            json={
                "schema_version": "agent_result_v1",
                "command_id": str(envelope.payload.command_id),
                "device_id": str(device.id),
                "status": "failed",
                "result_items": [],
                "message": "diagnostic unavailable",
                "completed_at": completed_at.isoformat(),
            },
        )

    assert response.status_code == 404
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        command = await session.get(Command, envelope.payload.command_id)
        result_count = await session.scalar(
            select(func.count()).select_from(CommandResult)
        )
    assert persisted is not None and collection is not None and command is not None
    assert persisted.status == command.status == "delivered"
    assert collection.status == "delivered"
    assert result_count == 0


@pytest.mark.asyncio
async def test_acknowledgements_monotonically_mirror_operation_lifecycle(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Ignoring ACK state would leave public work queued while the agent runs it."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    service = CommandService(session_provider)
    acknowledged_at = datetime.now(UTC)

    for status in ("acknowledged", "running", "acknowledged"):
        await service.record_ack(
            device_id=device.id,
            session_id=presence.session_id,
            acknowledgement=AgentCommandAckV1(
                schema_version="agent_command_ack_v1",
                command_id=envelope.payload.command_id,
                device_id=device.id,
                status=status,
                acknowledged_at=acknowledged_at,
            ),
        )

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        command = await session.get(Command, envelope.payload.command_id)
        delivery = await session.scalar(
            select(CommandDelivery).where(
                CommandDelivery.command_id == envelope.payload.command_id
            )
        )
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
    assert persisted is not None and command is not None and delivery is not None
    assert collection is not None
    assert persisted.status == command.status == delivery.status == "running"
    assert collection.status == "collecting"


@pytest.mark.asyncio
async def test_unacknowledged_operation_reconnect_reuses_persisted_command_identity(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Reconnect recovery must not materialize a second executable operation."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    instance_id = uuid4()
    first = await _open_session(
        session_provider,
        device_id=device.id,
        instance_id=instance_id,
    )
    first_envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=first.session_id,
    )
    reconnected = await _open_session(
        session_provider,
        device_id=device.id,
        instance_id=instance_id,
    )
    replayed_envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=reconnected.session_id,
    )

    assert replayed_envelope.payload == first_envelope.payload
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        assert await session.scalar(select(func.count()).select_from(Command)) == 1
        assert await session.scalar(select(func.count()).select_from(CommandDelivery)) == 1
        delivery = await session.scalar(select(CommandDelivery))
    assert persisted is not None and delivery is not None
    assert replayed_envelope.payload.command_id == persisted.command_id
    assert delivery.device_session_id == reconnected.session_id


@pytest.mark.asyncio
async def test_first_operation_result_requires_current_delivery_session_and_relation(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A valid device bearer alone must not authorize another session's delivery."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    first = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=first.session_id,
    )
    second = await _open_session(session_provider, device_id=device.id)
    result = _diagnostic_result(
        command_id=envelope.payload.command_id,
        device_id=device.id,
    )

    with pytest.raises(CommandStateRejected):
        await CommandService(session_provider).record_result(
            device_id=device.id,
            device_instance_id=second.device_instance_id,
            session_id=second.session_id,
            result_sequence=1,
            result=result,
        )

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        assert persisted is not None and persisted.status == "delivered"
        assert await session.scalar(select(func.count()).select_from(CommandResult)) == 0


@pytest.mark.asyncio
async def test_operation_result_requires_reciprocal_command_relation(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A broken operation-to-command link must fail closed before context ingestion."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        assert persisted is not None
        persisted.command_id = None
        await session.commit()

    with pytest.raises(CommandStateRejected):
        await CommandService(session_provider).record_result(
            device_id=device.id,
            device_instance_id=presence.device_instance_id,
            session_id=presence.session_id,
            result_sequence=1,
            result=_diagnostic_result(
                command_id=envelope.payload.command_id,
                device_id=device.id,
            ),
        )

    async with session_provider() as session:
        assert await session.scalar(select(func.count()).select_from(CommandResult)) == 0
        assert await session.scalar(select(func.count()).select_from(ContextSnapshot)) == 0


@pytest.mark.asyncio
async def test_success_result_is_validated_redacted_and_persisted_before_ack(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Terminal success must expose only a validated safe snapshot after commit."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    completed_at = datetime.now(UTC)
    result = _diagnostic_result(
        command_id=envelope.payload.command_id,
        device_id=device.id,
        completed_at=completed_at,
    )

    acknowledgement = await CommandService(session_provider).record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=7,
        result=result,
    )

    assert acknowledgement.payload.command_id == envelope.payload.command_id
    assert acknowledgement.payload.result_sequence == 7
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        snapshots = (await session.scalars(select(ContextSnapshot))).all()
        stored_results = (await session.scalars(select(CommandResult))).all()
        terminal_audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "endpoint.operation_succeeded"
                )
            )
        ).all()
    assert persisted is not None and collection is not None
    assert persisted.status == "succeeded"
    assert _utc(persisted.completed_at) == completed_at
    assert collection.status == "completed"
    assert len(snapshots) == len(stored_results) == 1
    assert len(terminal_audits) == 1
    persisted_json = json.dumps(
        {
            "raw": snapshots[0].raw_payload,
            "normalized": snapshots[0].normalized_projection,
            "collection": collection.raw_result_payload,
        },
        sort_keys=True,
    ).lower()
    assert "agent-secret" not in persisted_json
    assert "/srv/private" not in persisted_json
    safe_result = project_diagnostic_result(persisted, snapshots[0])
    assert safe_result is not None
    assert safe_result.log_excerpt == "[REDACTED]"
    assert [process.name for process in safe_result.processes] == ["[REDACTED]"]
    assert "redaction_applied" in safe_result.warnings


@pytest.mark.asyncio
async def test_failed_result_safely_terminalizes_operation_without_snapshot(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A bounded agent failure must map to failed without inventing a result."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    completed_at = datetime.now(UTC)
    acknowledgement = await CommandService(session_provider).record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=4,
        result=AgentResultV1(
            schema_version="agent_result_v1",
            command_id=envelope.payload.command_id,
            device_id=device.id,
            status="failed",
            result_items=[],
            message="token=agent-failure-secret",
            completed_at=completed_at,
        ),
    )

    assert acknowledgement.payload.result_sequence == 4
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        snapshots = (await session.scalars(select(ContextSnapshot))).all()
        terminal_audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "endpoint.operation_failed"
                )
            )
        ).all()
    assert persisted is not None and collection is not None
    assert persisted.status == "failed"
    assert _utc(persisted.completed_at) == completed_at
    assert collection.status == "failed"
    assert collection.failure_code == "command_failed"
    assert snapshots == []
    assert len(terminal_audits) == 1
    serialized = json.dumps(collection.raw_result_payload, sort_keys=True).lower()
    assert "agent-failure-secret" not in serialized


@pytest.mark.asyncio
async def test_mismatched_diagnostic_reason_rolls_back_without_result_ack(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Agent context for a different reason must not complete the server request."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )

    with pytest.raises(CommandStateRejected):
        await CommandService(session_provider).record_result(
            device_id=device.id,
            device_instance_id=presence.device_instance_id,
            session_id=presence.session_id,
            result_sequence=3,
            result=_diagnostic_result(
                command_id=envelope.payload.command_id,
                device_id=device.id,
                reason="Different agent-supplied reason",
            ),
        )

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        assert persisted is not None and persisted.status == "delivered"
        assert await session.scalar(select(func.count()).select_from(CommandResult)) == 0
        assert await session.scalar(select(func.count()).select_from(ContextSnapshot)) == 0


@pytest.mark.asyncio
async def test_reconnect_duplicate_is_idempotent_but_conflicting_result_rejects(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Reconnect replay may recover an ACK but must never replace terminal content."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    instance_id = uuid4()
    first = await _open_session(
        session_provider,
        device_id=device.id,
        instance_id=instance_id,
    )
    first_delivery = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=first.session_id,
    )
    service = CommandService(session_provider)
    result = _diagnostic_result(
        command_id=first_delivery.payload.command_id,
        device_id=device.id,
    )
    await service.record_result(
        device_id=device.id,
        device_instance_id=first.device_instance_id,
        session_id=first.session_id,
        result_sequence=9,
        result=result,
    )
    reconnected = await _open_session(
        session_provider,
        device_id=device.id,
        instance_id=instance_id,
    )

    duplicate_ack = await service.record_result(
        device_id=device.id,
        device_instance_id=reconnected.device_instance_id,
        session_id=reconnected.session_id,
        result_sequence=1,
        result=result,
    )
    assert duplicate_ack.payload.result_sequence == 1
    conflicting = result.model_copy(
        update={"message": "conflicting terminal replay"}
    )
    with pytest.raises(CommandStateRejected):
        await service.record_result(
            device_id=device.id,
            device_instance_id=reconnected.device_instance_id,
            session_id=reconnected.session_id,
            result_sequence=2,
            result=conflicting,
        )
    different_instance = await _open_session(
        session_provider,
        device_id=device.id,
        instance_id=uuid4(),
    )
    with pytest.raises(CommandStateRejected):
        await service.record_result(
            device_id=device.id,
            device_instance_id=different_instance.device_instance_id,
            session_id=different_instance.session_id,
            result_sequence=1,
            result=result,
        )

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        assert persisted is not None and persisted.status == "succeeded"
        assert await session.scalar(select(func.count()).select_from(Command)) == 1
        assert await session.scalar(select(func.count()).select_from(CommandDelivery)) == 1
        assert await session.scalar(select(func.count()).select_from(CommandResult)) == 1
        assert await session.scalar(select(func.count()).select_from(ContextSnapshot)) == 1


@pytest.mark.asyncio
async def test_worker_expiry_terminalizes_delivered_operation_transport(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Deadline expiry must run without an agent and prevent later transport work."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(
        session_provider,
        device_id=device.id,
    )
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        assert persisted is not None and collection is not None
        persisted.created_at = datetime.now(UTC) - timedelta(minutes=1)
        persisted.deadline_at = persisted.created_at + timedelta(seconds=1)
        collection.expires_at = persisted.deadline_at
        await session.commit()
    task = asyncio.create_task(
        run_worker(
            gateway_settings(),
            session_provider,
            cleanup_interval_seconds=0.01,
            context_schedule_interval_seconds=60,
            context_retention_interval_seconds=60,
        )
    )
    try:
        for _ in range(100):
            async with session_provider() as session:
                persisted = await session.get(EndpointOperation, operation.id)
                if persisted is not None and persisted.status == "expired":
                    break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("worker did not expire endpoint operation")
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        command = await session.get(Command, envelope.payload.command_id)
        delivery = await session.scalar(
            select(CommandDelivery).where(
                CommandDelivery.command_id == envelope.payload.command_id
            )
        )
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
    assert persisted is not None and command is not None and delivery is not None
    assert collection is not None
    assert persisted.status == command.status == delivery.status == "expired"
    assert collection.status == "expired"

    with pytest.raises(CommandStateRejected):
        await CommandService(session_provider).record_result(
            device_id=device.id,
            device_instance_id=presence.device_instance_id,
            session_id=presence.session_id,
            result_sequence=1,
            result=_diagnostic_result(
                command_id=envelope.payload.command_id,
                device_id=device.id,
            ),
        )
