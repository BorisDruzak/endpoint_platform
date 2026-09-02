"""Gateway-only delivery and atomic Endpoint Operation lifecycle linkage."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from endpoint_contracts import (
    AgentCommandAckV1,
    AgentHelloV1,
    AgentResultV1,
    DeviceContextDiagnosticV1,
    EndpointOperationCreateV1,
)
from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from endpoint_contracts.network_primitives import (
    DnsResolveResultV1,
    NetworkPingResultV1,
)
from endpoint_contracts.gateway_ws import CommandEnvelopeV1
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import (
    AuditEvent,
    Command,
    CommandDelivery,
    CommandResult,
    EndpointOperation,
    ModuleDefinition,
    ModuleOperationStep,
    ModuleVersion,
    ServiceClient,
)
from endpoint_server.gateway.command_service import (
    CommandService,
    CommandStateRejected,
    _safe_module_step_result,
    resolve_module_step_relation,
)
from endpoint_server.gateway.presence_service import GatewayPresence, PresenceService
from endpoint_server.main import create_app
from endpoint_server.operations.projection import project_diagnostic_result
from endpoint_server.operations.service import create_operation_outcome
from endpoint_server.modules.operation_service import create_module_parent_operation
from endpoint_server.policy.network_targets import NetworkTargetPolicyV1
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


async def _seed_module_operation(
    provider: async_sessionmaker[AsyncSession],
    *,
    device_id: UUID,
    version_state: str = "published",
    execution_mode: str = "published",
) -> EndpointOperation:
    recipe = EndpointRecipeModuleSpecV1.model_validate(
        {
            "schema_version": "endpoint_recipe_module_v1",
            "module_key": "network.dnsping",
            "supported_platforms": ["linux_amd64"],
            "inputs": [{"name": "target", "value_type": "string"}],
            "steps": [
                {
                    "step_id": "resolve",
                    "capability": "dns.resolve",
                    "parameters": {
                        "target": {"kind": "input", "name": "target"},
                        "family": {"kind": "literal", "value": "any"},
                    },
                },
                {
                    "step_id": "ping",
                    "capability": "network.ping",
                    "parameters": {
                        "target": {"kind": "input", "name": "target"},
                        "count": {"kind": "literal", "value": 1},
                        "timeout_ms": {"kind": "literal", "value": 500},
                    },
                },
            ],
        }
    )
    async with provider() as session:
        client = ServiceClient(
            id=uuid4(),
            client_identifier=f"module-helpdesk-{uuid4().hex}",
            display_name="Module Helpdesk",
        )
        definition = ModuleDefinition(
            id=uuid4(),
            created_at=datetime.now(UTC),
            module_key=recipe.module_key,
            display_name="DNS then ping",
        )
        session.add_all((client, definition))
        await session.flush()
        session.add(
            ModuleVersion(
                id=uuid4(),
                created_at=datetime.now(UTC),
                module_definition_id=definition.id,
                version="1.0.0",
                recipe=recipe.model_dump(mode="json"),
                state=version_state,
            )
        )
        await session.flush()
        operation, created = await create_module_parent_operation(
            session,
            service_client_id=client.id,
            device_id=device_id,
            module_key=recipe.module_key,
            version="1.0.0",
            inputs={"target": "probe.example.test"},
            idempotency_key=f"module-operation-{uuid4().hex}",
            network_policy=NetworkTargetPolicyV1.from_values(
                allowed_suffixes=(".example.test",),
                allowed_cidrs=(),
            ),
            execution_mode=execution_mode,
        )
        assert created is True
        await session.commit()
        return operation


async def _open_session(
    provider: async_sessionmaker[AsyncSession],
    *,
    device_id: UUID,
    instance_id: UUID | None = None,
    capabilities: list[str] | None = None,
) -> GatewayPresence:
    hello = agent_hello(device_id, instance_id=instance_id)
    hello["capabilities"] = capabilities or ["context.diagnostic.collect"]
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


async def _corrupt_collection_command_relation(
    provider: async_sessionmaker[AsyncSession],
    *,
    operation: EndpointOperation,
    operation_command_id: UUID,
    device_id: UUID,
    corruption: str,
) -> None:
    """Break only the collection side while preserving the operation command link."""
    async with provider() as session:
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        persisted = await session.get(EndpointOperation, operation.id)
        assert collection is not None and persisted is not None
        assert persisted.command_id == operation_command_id
        if corruption == "cleared":
            collection.command_id = None
        else:
            decoy = Command(
                id=uuid4(),
                created_at=datetime.now(UTC),
                command_identifier=f"decoy-{uuid4().hex}",
                device_id=device_id,
                command_kind="context.baseline.collect",
                status="delivered",
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
            session.add(decoy)
            await session.flush()
            collection.command_id = decoy.id
        await session.commit()


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
    assert operation.correlation is None
    assert "helpdesk" not in serialized.lower()


@pytest.mark.asyncio
async def test_validated_lab_parent_delivers_only_its_typed_child(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    await _seed_module_operation(
        session_provider,
        device_id=device.id,
        version_state="validated",
        execution_mode="lab",
    )
    presence = await _open_session(
        session_provider,
        device_id=device.id,
        capabilities=["dns.resolve", "network.ping"],
    )
    sent: list[CommandEnvelopeV1] = []

    delivered = await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        sent.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
        agent_platform="linux_amd64",
    )

    assert delivered is True
    assert len(sent) == 1
    assert sent[0].payload.capability == "dns.resolve"
    async with session_provider() as session:
        operation = await session.scalar(
            select(EndpointOperation).where(
                EndpointOperation.capability == "endpoint.module.recipe"
            )
        )
    assert operation is not None
    assert operation.parameters == {
        "execution_mode": "lab",
        "execution_platform": "linux_amd64",
    }


@pytest.mark.asyncio
async def test_lab_parent_latches_platform_only_when_a_child_is_delivered(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    await _seed_module_operation(
        session_provider,
        device_id=device.id,
        version_state="validated",
        execution_mode="lab",
    )
    presence = await _open_session(
        session_provider,
        device_id=device.id,
        capabilities=["network.ping"],
    )

    delivered = await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        lambda _: None,
        allowed_capabilities=frozenset({"network.ping"}),
        agent_platform="linux_amd64",
    )

    assert delivered is False
    async with session_provider() as session:
        operation = await session.scalar(
            select(EndpointOperation).where(
                EndpointOperation.capability == "endpoint.module.recipe"
            )
        )
    assert operation is not None
    assert operation.parameters == {"execution_mode": "lab"}


@pytest.mark.asyncio
async def test_module_parent_is_absent_from_http_pull_and_wss_delivers_one_typed_child(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """The agent receives a single primitive and cannot observe the module recipe."""
    device = await seed_device(session_provider)
    operation = await _seed_module_operation(session_provider, device_id=device.id)
    app = create_app(gateway_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
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

    presence = await _open_session(
        session_provider,
        device_id=device.id,
        capabilities=["dns.resolve", "network.ping"],
    )
    sent: list[CommandEnvelopeV1] = []
    assert await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        sent.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
    )
    assert len(sent) == 1
    payload = sent[0].payload
    serialized = json.dumps(payload.model_dump(mode="json"), sort_keys=True)
    assert payload.capability == "dns.resolve"
    assert payload.parameters == {"target": "probe.example.test", "family": "any"}
    assert payload.requested_by_service == "endpoint-platform"
    assert payload.idempotency_key.startswith(f"endpoint-module:{operation.id.hex}:")
    assert payload.correlation.request_id == operation.id
    assert payload.correlation.parent_command_id is None
    assert "recipe" not in serialized.lower()
    assert "network.ping" not in serialized

    replayed: list[CommandEnvelopeV1] = []
    assert await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        replayed.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
    )
    assert [item.payload.command_id for item in replayed] == [payload.command_id]

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        steps = (
            await session.scalars(
                select(ModuleOperationStep)
                .where(ModuleOperationStep.operation_id == operation.id)
                .order_by(ModuleOperationStep.sequence)
            )
        ).all()
        command = await session.get(Command, payload.command_id)
        delivery = await session.scalar(
            select(CommandDelivery).where(
                CommandDelivery.command_id == payload.command_id
            )
        )
        command_count = await session.scalar(select(func.count()).select_from(Command))
    assert persisted is not None and command is not None and delivery is not None
    assert persisted.status == "delivered"
    assert persisted.command_id is None
    assert [step.status for step in steps] == ["delivered", "queued"]
    assert steps[0].command_id == command.id
    assert delivery.device_session_id == presence.session_id
    assert command_count == 1


@pytest.mark.asyncio
async def test_module_child_ack_and_result_advance_the_next_typed_step(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    operation = await _seed_module_operation(session_provider, device_id=device.id)
    presence = await _open_session(
        session_provider,
        device_id=device.id,
        capabilities=["dns.resolve", "network.ping"],
    )
    first: list[CommandEnvelopeV1] = []
    assert await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        first.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
    )
    first_payload = first[0].payload
    acknowledged_at = datetime.now(UTC)
    await CommandService(session_provider).record_ack(
        device_id=device.id,
        session_id=presence.session_id,
        acknowledgement=AgentCommandAckV1(
            schema_version="agent_command_ack_v1",
            command_id=first_payload.command_id,
            device_id=device.id,
            status="running",
            acknowledged_at=acknowledged_at,
        ),
    )
    dns_result = DnsResolveResultV1(
        schema_version="dns_resolve_result_v1",
        target="probe.example.test",
        canonical_name=None,
        addresses=[],
        address_count=0,
        status="succeeded",
        error_code=None,
        collected_at=acknowledged_at,
    )
    await CommandService(session_provider).record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=1,
        result=AgentResultV1(
            schema_version="agent_result_v1",
            command_id=first_payload.command_id,
            device_id=device.id,
            status="succeeded",
            result_items=[dns_result.model_dump(mode="json")],
            completed_at=acknowledged_at,
        ),
    )
    second: list[CommandEnvelopeV1] = []
    assert await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        second.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
    )
    second_payload = second[0].payload
    assert second_payload.command_id != first_payload.command_id
    assert second_payload.capability == "network.ping"
    assert second_payload.parameters == {
        "target": "probe.example.test",
        "count": 1,
        "timeout_ms": 500,
    }

    await CommandService(session_provider).record_ack(
        device_id=device.id,
        session_id=presence.session_id,
        acknowledgement=AgentCommandAckV1(
            schema_version="agent_command_ack_v1",
            command_id=second_payload.command_id,
            device_id=device.id,
            status="running",
            acknowledged_at=acknowledged_at,
        ),
    )
    ping_result = NetworkPingResultV1(
        schema_version="network_ping_result_v1",
        target="probe.example.test",
        resolved_ip=None,
        transmitted=1,
        received=0,
        packet_loss_percent=100.0,
        min_ms=None,
        avg_ms=None,
        max_ms=None,
        reachable=False,
        status="succeeded",
        error_code=None,
        collected_at=acknowledged_at,
    )
    await CommandService(session_provider).record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=2,
        result=AgentResultV1(
            schema_version="agent_result_v1",
            command_id=second_payload.command_id,
            device_id=device.id,
            status="succeeded",
            result_items=[ping_result.model_dump(mode="json")],
            completed_at=acknowledged_at,
        ),
    )
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        steps = (
            await session.scalars(
                select(ModuleOperationStep)
                .where(ModuleOperationStep.operation_id == operation.id)
                .order_by(ModuleOperationStep.sequence)
            )
        ).all()
        audit = await session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "endpoint.module_operation_completed",
                AuditEvent.object_identifier == str(operation.id),
            )
        )
    assert persisted is not None
    assert persisted.status == "succeeded"
    assert persisted.completed_at is not None
    assert [step.status for step in steps] == ["succeeded", "succeeded"]
    assert all(step.safe_result_json is not None for step in steps)
    assert audit is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("result_status", ["succeeded", "failed"])
async def test_module_terminal_result_rejects_a_truncated_authoritative_child_set(
    session_provider: async_sessionmaker[AsyncSession],
    result_status: str,
) -> None:
    """A missing tail cannot terminalize a parent operation."""
    device = await seed_device(session_provider)
    operation = await _seed_module_operation(session_provider, device_id=device.id)
    presence = await _open_session(
        session_provider,
        device_id=device.id,
        capabilities=["dns.resolve", "network.ping"],
    )
    delivered: list[CommandEnvelopeV1] = []
    assert await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        delivered.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
    )
    payload = delivered[0].payload
    async with session_provider() as session:
        await session.execute(
            delete(ModuleOperationStep).where(
                ModuleOperationStep.operation_id == operation.id,
                ModuleOperationStep.sequence == 1,
            )
        )
        await session.commit()

    completed_at = datetime.now(UTC)
    result_items = []
    if result_status == "succeeded":
        result_items = [
            DnsResolveResultV1(
                schema_version="dns_resolve_result_v1",
                target="probe.example.test",
                canonical_name=None,
                addresses=[],
                address_count=0,
                status="succeeded",
                error_code=None,
                collected_at=completed_at,
            ).model_dump(mode="json")
        ]
    with pytest.raises(CommandStateRejected, match="step set"):
        await CommandService(session_provider).record_result(
            device_id=device.id,
            device_instance_id=presence.device_instance_id,
            session_id=presence.session_id,
            result_sequence=1,
            result=AgentResultV1(
                schema_version="agent_result_v1",
                command_id=payload.command_id,
                device_id=device.id,
                status=result_status,
                result_items=result_items,
                completed_at=completed_at,
            ),
        )


@pytest.mark.asyncio
async def test_module_result_relation_locks_parent_before_child_like_replay() -> None:
    """Gateway result handling must share the replay path's parent-to-child order."""
    device_id = uuid4()
    operation_id = uuid4()
    step = ModuleOperationStep(
        id=uuid4(),
        operation_id=operation_id,
        command_id=uuid4(),
        capability="dns.resolve",
    )
    operation = EndpointOperation(
        id=operation_id,
        device_id=device_id,
        capability="endpoint.module.recipe",
        command_id=None,
    )
    command = Command(
        id=step.command_id,
        device_id=device_id,
        command_kind="dns.resolve",
    )

    class RecordingSession:
        def __init__(self) -> None:
            self.statements: list[object] = []

        async def scalar(self, statement: object) -> object:
            self.statements.append(statement)
            descriptions = getattr(statement, "column_descriptions")
            entity = descriptions[0].get("entity")
            if entity is EndpointOperation:
                return operation
            if getattr(statement, "_for_update_arg") is None:
                return operation_id
            return step

    session = RecordingSession()
    relation = await resolve_module_step_relation(session, command)

    assert relation == (step, operation)
    assert [
        (
            statement.column_descriptions[0].get("entity"),
            statement._for_update_arg is not None,
        )
        for statement in session.statements
    ] == [
        (ModuleOperationStep, False),
        (EndpointOperation, True),
        (ModuleOperationStep, True),
    ]


@pytest.mark.asyncio
async def test_module_result_replay_rejects_a_truncated_authoritative_child_set(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Replaying an accepted result cannot hide later child-set corruption."""
    device = await seed_device(session_provider)
    operation = await _seed_module_operation(session_provider, device_id=device.id)
    presence = await _open_session(
        session_provider,
        device_id=device.id,
        capabilities=["dns.resolve", "network.ping"],
    )
    delivered: list[CommandEnvelopeV1] = []
    assert await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        delivered.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
    )
    completed_at = datetime.now(UTC)
    result = AgentResultV1(
        schema_version="agent_result_v1",
        command_id=delivered[0].payload.command_id,
        device_id=device.id,
        status="succeeded",
        result_items=[
            DnsResolveResultV1(
                schema_version="dns_resolve_result_v1",
                target="probe.example.test",
                canonical_name=None,
                addresses=[],
                address_count=0,
                status="succeeded",
                error_code=None,
                collected_at=completed_at,
            ).model_dump(mode="json")
        ],
        completed_at=completed_at,
    )
    service = CommandService(session_provider)
    await service.record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=1,
        result=result,
    )
    async with session_provider() as session:
        await session.execute(
            delete(ModuleOperationStep).where(
                ModuleOperationStep.operation_id == operation.id,
                ModuleOperationStep.sequence == 1,
            )
        )
        await session.commit()

    with pytest.raises(CommandStateRejected, match="step set"):
        await service.record_result(
            device_id=device.id,
            device_instance_id=presence.device_instance_id,
            session_id=presence.session_id,
            result_sequence=2,
            result=result,
        )


@pytest.mark.parametrize(
    ("capability", "result_item", "expected_schema_version"),
    [
        (
            "route.get",
            {
                "schema_version": "route_get_result_v1",
                "target": "probe.example.test",
                "resolved_ip": "192.0.2.10",
                "family": "ipv4",
                "port": 443,
                "source_ip": "192.0.2.20",
                "interface_name": "eth0",
                "strategy": "udp_socket_inference",
                "status": "succeeded",
                "error_code": None,
                "collected_at": "2026-08-28T00:00:00Z",
            },
            "route_get_result_v1",
        ),
        (
            "adapter.list",
            {
                "schema_version": "adapter_list_result_v1",
                "adapters": [],
                "adapter_count": 0,
                "up_count": 0,
                "status": "succeeded",
                "error_code": None,
                "collected_at": "2026-08-28T00:00:00Z",
            },
            "adapter_list_result_v1",
        ),
        (
            "system.service_status",
            {
                "schema_version": "service_status_result_v1",
                "service_key": "endpoint_agent",
                "installed": False,
                "state": "not_found",
                "start_mode": "unknown",
                "status": "succeeded",
                "error_code": None,
                "collected_at": "2026-08-28T00:00:00Z",
            },
            "service_status_result_v1",
        ),
    ],
)
def test_module_result_processing_accepts_every_read_only_registry_dto(
    capability: str,
    result_item: dict[str, object],
    expected_schema_version: str,
) -> None:
    """A completed registered read-only step persists its declared DTO only."""
    result, error_code = _safe_module_step_result(
        ModuleOperationStep(capability=capability),
        AgentResultV1(
            schema_version="agent_result_v1",
            command_id=UUID("11111111-1111-4111-8111-111111111111"),
            device_id=UUID("22222222-2222-4222-8222-222222222222"),
            status="succeeded",
            result_items=[result_item],
            completed_at=datetime(2026, 8, 28, tzinfo=UTC),
        ),
    )

    assert error_code is None
    assert result is not None
    assert result["schema_version"] == expected_schema_version


@pytest.mark.asyncio
async def test_failed_module_child_stops_the_remaining_recipe_steps(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    operation = await _seed_module_operation(session_provider, device_id=device.id)
    presence = await _open_session(
        session_provider,
        device_id=device.id,
        capabilities=["dns.resolve", "network.ping"],
    )
    delivered: list[CommandEnvelopeV1] = []
    assert await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        delivered.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
    )
    payload = delivered[0].payload
    completed_at = datetime.now(UTC)
    await CommandService(session_provider).record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=1,
        result=AgentResultV1(
            schema_version="agent_result_v1",
            command_id=payload.command_id,
            device_id=device.id,
            status="failed",
            result_items=[],
            message="untrusted raw detail is intentionally ignored",
            completed_at=completed_at,
        ),
    )
    next_delivery: list[CommandEnvelopeV1] = []
    assert not await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        next_delivery.append,
        allowed_capabilities=frozenset({"dns.resolve", "network.ping"}),
    )
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        steps = (
            await session.scalars(
                select(ModuleOperationStep)
                .where(ModuleOperationStep.operation_id == operation.id)
                .order_by(ModuleOperationStep.sequence)
            )
        ).all()
        audit = await session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "endpoint.module_operation_failed",
                AuditEvent.object_identifier == str(operation.id),
            )
        )
    assert persisted is not None and persisted.status == "failed"
    assert [step.status for step in steps] == ["failed", "queued"]
    assert steps[0].safe_result_json is None
    assert steps[0].error_code == "module_step_failed"
    assert audit is not None


@pytest.mark.asyncio
async def test_operation_expired_before_first_wss_delivery_is_never_sent(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A connect after the deadline must expire queued work before materializing it."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(
        session_provider,
        device_id=device.id,
        now=datetime.now(UTC) - timedelta(minutes=16),
    )
    presence = await _open_session(session_provider, device_id=device.id)
    sent: list[CommandEnvelopeV1] = []

    delivered = await CommandService(session_provider).deliver_next(
        device.id,
        presence.session_id,
        sent.append,
        allowed_capabilities=frozenset({"context.diagnostic.collect"}),
    )

    assert delivered is False
    assert sent == []
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        command_count = await session.scalar(select(func.count()).select_from(Command))
        delivery_count = await session.scalar(
            select(func.count()).select_from(CommandDelivery)
        )
        expiry_audit_count = await session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "endpoint.operation_expired")
        )
    assert persisted is not None and collection is not None
    assert persisted.status == collection.status == "expired"
    assert persisted.completed_at is not None
    assert _utc(persisted.completed_at) >= _utc(operation.deadline_at)
    assert collection.failure_code == "operation_expired"
    assert command_count == delivery_count == 0
    assert expiry_audit_count == 1


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


@pytest.mark.parametrize("corruption", ["cleared", "mismatched"])
@pytest.mark.asyncio
async def test_http_rejects_operation_command_when_collection_command_link_is_corrupt(
    session_provider: async_sessionmaker[AsyncSession],
    corruption: str,
) -> None:
    """A direct operation command link must never fall through to legacy HTTP."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    command_id = envelope.payload.command_id
    await _corrupt_collection_command_relation(
        session_provider,
        operation=operation,
        operation_command_id=command_id,
        device_id=device.id,
        corruption=corruption,
    )
    timestamp = datetime.now(UTC)
    app = create_app(gateway_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=app,
            client=("127.0.0.1", 12345),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        ack_response = await client.post(
            f"/agent/v1/gateway/commands/{command_id}/ack",
            headers={
                "Authorization": f"Bearer {VALID_TOKEN}",
                "X-Forwarded-For": "192.168.101.20",
            },
            json={
                "schema_version": "agent_command_ack_v1",
                "command_id": str(command_id),
                "device_id": str(device.id),
                "status": "acknowledged",
                "acknowledged_at": timestamp.isoformat(),
                "message": None,
            },
        )
        result_response = await client.post(
            f"/agent/v1/gateway/commands/{command_id}/results",
            headers={
                "Authorization": f"Bearer {VALID_TOKEN}",
                "X-Forwarded-For": "192.168.101.20",
            },
            json={
                "schema_version": "agent_result_v1",
                "command_id": str(command_id),
                "device_id": str(device.id),
                "status": "failed",
                "result_items": [],
                "message": "diagnostic unavailable",
                "completed_at": timestamp.isoformat(),
            },
        )

    assert ack_response.status_code == 404
    assert result_response.status_code == 404
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        command = await session.get(Command, command_id)
        delivery = await session.scalar(
            select(CommandDelivery).where(CommandDelivery.command_id == command_id)
        )
        result_count = await session.scalar(
            select(func.count()).select_from(CommandResult)
        )
    assert persisted is not None and command is not None and delivery is not None
    assert persisted.status == command.status == delivery.status == "delivered"
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
        assert (
            await session.scalar(select(func.count()).select_from(CommandDelivery)) == 1
        )
        delivery = await session.scalar(select(CommandDelivery))
    assert persisted is not None and delivery is not None
    assert replayed_envelope.payload.command_id == persisted.command_id
    assert delivery.device_session_id == reconnected.session_id


@pytest.mark.asyncio
async def test_operation_expired_before_wss_replay_is_terminalized_not_resent(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Reconnect replay must re-check server time before exposing durable work."""
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
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        command = await session.get(Command, first_envelope.payload.command_id)
        assert persisted is not None and command is not None
        persisted.created_at = expired_at - timedelta(minutes=15)
        persisted.deadline_at = expired_at
        command.created_at = expired_at - timedelta(minutes=14)
        command.expires_at = expired_at
        await session.commit()
    reconnected = await _open_session(
        session_provider,
        device_id=device.id,
        instance_id=instance_id,
    )
    replayed: list[CommandEnvelopeV1] = []

    delivered = await CommandService(session_provider).deliver_next(
        device.id,
        reconnected.session_id,
        replayed.append,
        allowed_capabilities=frozenset({"context.diagnostic.collect"}),
    )

    assert delivered is False
    assert replayed == []
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        command = await session.get(Command, first_envelope.payload.command_id)
        deliveries = (await session.scalars(select(CommandDelivery))).all()
        expiry_audit_count = await session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "endpoint.operation_expired")
        )
    assert persisted is not None and collection is not None and command is not None
    assert len(deliveries) == 1
    assert (
        persisted.status
        == collection.status
        == command.status
        == deliveries[0].status
        == "expired"
    )
    assert persisted.command_id == first_envelope.payload.command_id
    assert collection.command_id == first_envelope.payload.command_id
    assert expiry_audit_count == 1


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
        assert (
            await session.scalar(select(func.count()).select_from(CommandResult)) == 0
        )


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
        assert (
            await session.scalar(select(func.count()).select_from(CommandResult)) == 0
        )
        assert (
            await session.scalar(select(func.count()).select_from(ContextSnapshot)) == 0
        )


@pytest.mark.parametrize("corruption", ["cleared", "mismatched"])
@pytest.mark.asyncio
async def test_wss_ack_rejects_operation_when_collection_command_link_is_corrupt(
    session_provider: async_sessionmaker[AsyncSession],
    corruption: str,
) -> None:
    """WSS ACK classification must honor the direct operation command owner."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    command_id = envelope.payload.command_id
    await _corrupt_collection_command_relation(
        session_provider,
        operation=operation,
        operation_command_id=command_id,
        device_id=device.id,
        corruption=corruption,
    )

    with pytest.raises(CommandStateRejected):
        await CommandService(session_provider).record_ack(
            device_id=device.id,
            session_id=presence.session_id,
            acknowledgement=AgentCommandAckV1(
                schema_version="agent_command_ack_v1",
                command_id=command_id,
                device_id=device.id,
                status="acknowledged",
                acknowledged_at=datetime.now(UTC),
            ),
        )

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        command = await session.get(Command, command_id)
        delivery = await session.scalar(
            select(CommandDelivery).where(CommandDelivery.command_id == command_id)
        )
    assert persisted is not None and command is not None and delivery is not None
    assert persisted.status == command.status == delivery.status == "delivered"


@pytest.mark.parametrize("corruption", ["cleared", "mismatched"])
@pytest.mark.asyncio
async def test_wss_result_rejects_without_ack_when_collection_command_link_is_corrupt(
    session_provider: async_sessionmaker[AsyncSession],
    corruption: str,
) -> None:
    """A corrupt operation relation must roll back before a WSS result ACK exists."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    command_id = envelope.payload.command_id
    await _corrupt_collection_command_relation(
        session_provider,
        operation=operation,
        operation_command_id=command_id,
        device_id=device.id,
        corruption=corruption,
    )

    with pytest.raises(CommandStateRejected):
        await CommandService(session_provider).record_result(
            device_id=device.id,
            device_instance_id=presence.device_instance_id,
            session_id=presence.session_id,
            result_sequence=1,
            result=AgentResultV1(
                schema_version="agent_result_v1",
                command_id=command_id,
                device_id=device.id,
                status="failed",
                result_items=[],
                message="diagnostic unavailable",
                completed_at=datetime.now(UTC),
            ),
        )

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        command = await session.get(Command, command_id)
        delivery = await session.scalar(
            select(CommandDelivery).where(CommandDelivery.command_id == command_id)
        )
        result_count = await session.scalar(
            select(func.count()).select_from(CommandResult)
        )
        snapshot_count = await session.scalar(
            select(func.count()).select_from(ContextSnapshot)
        )
    assert persisted is not None and command is not None and delivery is not None
    assert persisted.status == command.status == delivery.status == "delivered"
    assert result_count == snapshot_count == 0


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
        delivery = await session.scalar(
            select(CommandDelivery).where(
                CommandDelivery.command_id == envelope.payload.command_id
            )
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
    assert persisted is not None and collection is not None and delivery is not None
    assert persisted.status == delivery.status == "succeeded"
    assert _utc(persisted.completed_at) >= completed_at
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
        delivery = await session.scalar(
            select(CommandDelivery).where(
                CommandDelivery.command_id == envelope.payload.command_id
            )
        )
        snapshots = (await session.scalars(select(ContextSnapshot))).all()
        terminal_audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "endpoint.operation_failed"
                )
            )
        ).all()
    assert persisted is not None and collection is not None and delivery is not None
    assert persisted.status == delivery.status == "failed"
    assert _utc(persisted.completed_at) >= completed_at
    assert collection.status == "failed"
    assert collection.failure_code == "command_failed"
    assert snapshots == []
    assert len(terminal_audits) == 1
    serialized = json.dumps(collection.raw_result_payload, sort_keys=True).lower()
    assert "agent-failure-secret" not in serialized


@pytest.mark.asyncio
async def test_result_received_after_server_deadline_cannot_complete_operation(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """The locked server deadline, not the agent timestamp, decides acceptance."""
    server_now = datetime.now(UTC)
    device = await seed_device(session_provider)
    operation = await _seed_operation(
        session_provider,
        device_id=device.id,
        now=server_now - timedelta(minutes=1),
    )
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        command = await session.get(Command, envelope.payload.command_id)
        assert persisted is not None and command is not None
        persisted.deadline_at = server_now - timedelta(seconds=1)
        command.expires_at = persisted.deadline_at
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
                completed_at=server_now - timedelta(seconds=2),
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
        result_count = await session.scalar(
            select(func.count()).select_from(CommandResult)
        )
    assert persisted is not None and command is not None and delivery is not None
    assert persisted.status == command.status == delivery.status == "delivered"
    assert result_count == 0


@pytest.mark.asyncio
async def test_terminal_operation_uses_server_acceptance_time_not_agent_future_time(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """Permitted clock skew must not control public or audit completion time."""
    device = await seed_device(session_provider)
    operation = await _seed_operation(session_provider, device_id=device.id)
    presence = await _open_session(session_provider, device_id=device.id)
    envelope = await _deliver_operation(
        session_provider,
        device_id=device.id,
        session_id=presence.session_id,
    )
    acceptance_lower_bound = datetime.now(UTC)
    agent_completed_at = acceptance_lower_bound + timedelta(seconds=30)

    await CommandService(session_provider).record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=1,
        result=_diagnostic_result(
            command_id=envelope.payload.command_id,
            device_id=device.id,
            completed_at=agent_completed_at,
        ),
    )
    acceptance_upper_bound = datetime.now(UTC)

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        stored = await session.scalar(select(CommandResult))
        collection = await session.get(
            ContextCollection,
            operation.context_collection_id,
        )
        audit = await session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "endpoint.operation_succeeded"
            )
        )
    assert persisted is not None and stored is not None and collection is not None
    assert audit is not None
    for server_owned_timestamp in (
        persisted.completed_at,
        stored.completed_at,
        collection.completed_at,
        audit.created_at,
    ):
        assert server_owned_timestamp is not None
        assert (
            acceptance_lower_bound
            <= _utc(server_owned_timestamp)
            <= acceptance_upper_bound
        )
        assert _utc(server_owned_timestamp) != agent_completed_at


@pytest.mark.asyncio
async def test_materially_future_operation_completion_time_is_rejected(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """An agent clock far in the future must not create terminal state or audits."""
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
            result_sequence=1,
            result=_diagnostic_result(
                command_id=envelope.payload.command_id,
                device_id=device.id,
                completed_at=datetime.now(UTC) + timedelta(hours=1),
            ),
        )

    async with session_provider() as session:
        persisted = await session.get(EndpointOperation, operation.id)
        delivery = await session.scalar(
            select(CommandDelivery).where(
                CommandDelivery.command_id == envelope.payload.command_id
            )
        )
        result_count = await session.scalar(
            select(func.count()).select_from(CommandResult)
        )
        terminal_audit_count = await session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "endpoint.operation_succeeded")
        )
    assert persisted is not None and delivery is not None
    assert persisted.status == delivery.status == "delivered"
    assert result_count == terminal_audit_count == 0


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
        assert (
            await session.scalar(select(func.count()).select_from(CommandResult)) == 0
        )
        assert (
            await session.scalar(select(func.count()).select_from(ContextSnapshot)) == 0
        )


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
    conflicting = result.model_copy(update={"message": "conflicting terminal replay"})
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
        delivery = await session.scalar(
            select(CommandDelivery).where(
                CommandDelivery.command_id == first_delivery.payload.command_id
            )
        )
        assert persisted is not None and persisted.status == "succeeded"
        assert delivery is not None and delivery.status == "succeeded"
        assert await session.scalar(select(func.count()).select_from(Command)) == 1
        assert (
            await session.scalar(select(func.count()).select_from(CommandDelivery)) == 1
        )
        assert (
            await session.scalar(select(func.count()).select_from(CommandResult)) == 1
        )
        assert (
            await session.scalar(select(func.count()).select_from(ContextSnapshot)) == 1
        )


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
