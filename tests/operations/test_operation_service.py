"""Persisted, service-scoped Endpoint Operation behavior."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import ForeignKeyConstraint, UniqueConstraint, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from endpoint_contracts import EndpointOperationCreateV1
from endpoint_server.operations.projection import project_operation
from endpoint_server.operations.service import (
    OperationConflict,
    OperationNotFound,
    create_operation_outcome,
    expire_operations,
    read_operation_for_service,
)
from endpoint_server.db.models import (
    AuditEvent,
    Command,
    CommandResult,
    ContextCollection,
    Device,
    EndpointOperation,
    ModuleDefinition,
    ModuleVersion,
    ServiceClient,
)


NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
KEY = "operation-key-0001"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _request(
    *,
    reason: str = "Collect bounded diagnostic context",
) -> EndpointOperationCreateV1:
    return EndpointOperationCreateV1.model_validate(
        {
            "schema_version": "endpoint_operation_create_v1",
            "capability": "context.diagnostic.collect",
            "parameters": {"reason": reason},
        }
    )


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        ServiceClient.__table__,
        Device.__table__,
        Command.__table__,
        CommandResult.__table__,
        AuditEvent.__table__,
        ContextCollection.__table__,
        ModuleDefinition.__table__,
        ModuleVersion.__table__,
        EndpointOperation.__table__,
    )
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(sync, tables=tables)
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as value:
        yield value
    await engine.dispose()


async def _ownership(
    session: AsyncSession,
    *,
    client_identifier: str = "helpdesk",
    retired_at: datetime | None = None,
) -> tuple[ServiceClient, Device]:
    client = ServiceClient(
        id=uuid4(),
        client_identifier=client_identifier,
        display_name=client_identifier.title(),
    )
    device = Device(
        id=uuid4(),
        device_identifier=f"device-{uuid4().hex}",
        display_name="Endpoint",
        retired_at=retired_at,
    )
    session.add_all((client, device))
    await session.flush()
    return client, device


@pytest.mark.asyncio
async def test_exact_service_key_replay_returns_same_operation(
    session: AsyncSession,
) -> None:
    """Removing client/key replay would duplicate private diagnostic work."""
    client, device = await _ownership(session)
    request = _request()

    first, created = await create_operation_outcome(
        session,
        request=request,
        service_client_id=client.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW,
    )
    replay, replayed = await create_operation_outcome(
        session,
        request=request,
        service_client_id=client.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW + timedelta(seconds=1),
    )

    assert created is True
    assert replayed is False
    assert replay.id == first.id
    assert len((await session.scalars(select(EndpointOperation))).all()) == 1
    collections = (await session.scalars(select(ContextCollection))).all()
    assert len(collections) == 1
    assert collections[0].operation_id == first.id
    assert first.context_collection_id == collections[0].id
    assert [
        event.action
        for event in (
            await session.scalars(select(AuditEvent).order_by(AuditEvent.created_at))
        ).all()
    ] == ["endpoint.operation_created", "endpoint.operation_replayed"]


@pytest.mark.asyncio
async def test_same_key_is_independent_across_service_clients(
    session: AsyncSession,
) -> None:
    """Scoping only by the key would let one service replay another's request."""
    first_client, device = await _ownership(session, client_identifier="helpdesk-a")
    second_client = ServiceClient(
        id=uuid4(),
        client_identifier="helpdesk-b",
        display_name="Helpdesk B",
    )
    session.add(second_client)
    await session.flush()

    first, first_created = await create_operation_outcome(
        session,
        request=_request(),
        service_client_id=first_client.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW,
    )
    second, second_created = await create_operation_outcome(
        session,
        request=_request(),
        service_client_id=second_client.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW,
    )

    assert first_created is True and second_created is True
    assert first.id != second.id
    assert len((await session.scalars(select(EndpointOperation))).all()) == 2


@pytest.mark.asyncio
async def test_same_client_key_rejects_payload_or_device_mismatch_with_stable_code(
    session: AsyncSession,
) -> None:
    """Reusing a key for different normalized intent must never replay work."""
    client, first_device = await _ownership(session)
    second_device = Device(
        id=uuid4(),
        device_identifier="device-conflict-target",
        display_name="Other endpoint",
    )
    session.add(second_device)
    await session.flush()
    await create_operation_outcome(
        session,
        request=_request(),
        service_client_id=client.id,
        device_id=first_device.id,
        idempotency_key=KEY,
        now=NOW,
    )

    for request, device_id in (
        (_request(reason="Different normalized diagnostic reason"), first_device.id),
        (_request(), second_device.id),
    ):
        with pytest.raises(OperationConflict) as rejected:
            await create_operation_outcome(
                session,
                request=request,
                service_client_id=client.id,
                device_id=device_id,
                idempotency_key=KEY,
                now=NOW,
            )
        assert rejected.value.code == "endpoint_operation_idempotency_conflict"

    assert len((await session.scalars(select(EndpointOperation))).all()) == 1
    assert len((await session.scalars(select(ContextCollection))).all()) == 1


@pytest.mark.asyncio
async def test_creation_requires_an_existing_active_device(
    session: AsyncSession,
) -> None:
    """Retired or unknown devices must not receive new private work."""
    active_client, retired_device = await _ownership(
        session,
        retired_at=NOW - timedelta(days=1),
    )

    for device_id in (retired_device.id, uuid4()):
        with pytest.raises(OperationNotFound) as rejected:
            await create_operation_outcome(
                session,
                request=_request(),
                service_client_id=active_client.id,
                device_id=device_id,
                idempotency_key=KEY,
                now=NOW,
            )
        assert rejected.value.code == "endpoint_operation_device_not_found"

    assert (await session.scalars(select(EndpointOperation))).all() == []


@pytest.mark.asyncio
async def test_creation_persists_bounded_private_request_and_redacted_audit_together(
    session: AsyncSession,
) -> None:
    """Audit storage must not copy request parameters or idempotency."""
    client, device = await _ownership(session)
    reason = "Inspect token: this-must-stay-out-of-audit"

    operation, created = await create_operation_outcome(
        session,
        request=_request(reason=reason),
        service_client_id=client.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW,
    )
    await session.commit()

    assert created is True
    assert operation.parameters == {"reason": reason}
    assert operation.correlation is None
    collection = await session.scalar(
        select(ContextCollection).where(ContextCollection.operation_id == operation.id)
    )
    event = await session.scalar(
        select(AuditEvent).where(AuditEvent.action == "endpoint.operation_created")
    )
    assert collection is not None
    assert collection.profile == "diagnostic_v1"
    assert collection.requested_by == f"endpoint-operation:{client.id.hex}"
    assert collection.expires_at is not None
    assert _utc(collection.expires_at) == _utc(operation.deadline_at)
    assert event is not None
    assert event.request_id == f"operation-{operation.id.hex}"
    assert event.object_identifier == str(operation.id)
    audit_json = json.dumps(event.details, sort_keys=True)
    assert reason not in audit_json
    assert KEY not in audit_json


@pytest.mark.asyncio
async def test_creation_leaves_commit_and_rollback_to_the_caller(
    session: AsyncSession,
) -> None:
    """A service-level commit would break atomic composition with the route transaction."""
    client, device = await _ownership(session)
    await session.commit()

    await create_operation_outcome(
        session,
        request=_request(),
        service_client_id=client.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW,
    )
    await session.rollback()

    assert (await session.scalars(select(EndpointOperation))).all() == []
    assert (await session.scalars(select(ContextCollection))).all() == []
    assert (await session.scalars(select(AuditEvent))).all() == []


@pytest.mark.asyncio
async def test_read_is_scoped_to_service_client_and_appends_safe_audit(
    session: AsyncSession,
) -> None:
    """Credential rotation may preserve access, but another client never gains it."""
    owner, device = await _ownership(session, client_identifier="operation-owner")
    foreign = ServiceClient(
        id=uuid4(),
        client_identifier="operation-foreign",
        display_name="Foreign",
    )
    session.add(foreign)
    await session.flush()
    operation, _ = await create_operation_outcome(
        session,
        request=_request(),
        service_client_id=owner.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW,
    )

    observed = await read_operation_for_service(
        session,
        operation_id=operation.id,
        service_client_id=owner.id,
        now=NOW + timedelta(seconds=2),
    )
    assert observed.id == operation.id
    with pytest.raises(OperationNotFound):
        await read_operation_for_service(
            session,
            operation_id=operation.id,
            service_client_id=foreign.id,
            now=NOW + timedelta(seconds=3),
        )
    actions = list(await session.scalars(select(AuditEvent.action)))
    assert actions.count("endpoint.operation_read") == 1


@pytest.mark.asyncio
async def test_expiry_atomically_terminalizes_operation_and_private_collection(
    session: AsyncSession,
) -> None:
    """Offline operation work must not remain queued after its server deadline."""
    client, device = await _ownership(session)
    operation, _ = await create_operation_outcome(
        session,
        request=_request(),
        service_client_id=client.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW,
    )

    assert await expire_operations(session, now=operation.deadline_at, limit=10) == 1
    assert await expire_operations(
        session, now=operation.deadline_at + timedelta(seconds=1), limit=10
    ) == 0
    collection = await session.scalar(
        select(ContextCollection).where(ContextCollection.operation_id == operation.id)
    )
    assert operation.status == "expired"
    assert operation.completed_at == operation.deadline_at
    assert collection is not None
    assert collection.status == "expired"
    assert collection.failed_at is not None
    assert _utc(collection.failed_at) == _utc(operation.deadline_at)
    assert collection.failure_code == "operation_expired"
    assert list(await session.scalars(select(AuditEvent.action))).count(
        "endpoint.operation_expired"
    ) == 1


@pytest.mark.asyncio
async def test_projection_excludes_private_operation_storage(
    session: AsyncSession,
) -> None:
    """Projection must not expose parameters, idempotency, client, collection, or command."""
    client, device = await _ownership(session)
    operation, _ = await create_operation_outcome(
        session,
        request=_request(),
        service_client_id=client.id,
        device_id=device.id,
        idempotency_key=KEY,
        now=NOW,
    )

    projected = project_operation(operation).model_dump(mode="json")

    assert projected["operation_id"] == str(operation.id)
    assert "correlation" not in projected
    assert not {
        "parameters",
        "idempotency_key",
        "requested_by_service_client_id",
        "context_collection_id",
        "command_id",
    }.intersection(projected)


def test_model_relations_enforce_unambiguous_one_to_one_ownership() -> None:
    """Independent nullable pointers could otherwise cross-link operation records."""
    operation_uniques = {
        tuple(constraint.columns.keys())
        for constraint in EndpointOperation.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    collection_uniques = {
        tuple(constraint.columns.keys())
        for constraint in ContextCollection.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    collection_foreign_keys = {
        (
            tuple(constraint.columns.keys()),
            tuple(element.target_fullname for element in constraint.elements),
        )
        for constraint in ContextCollection.__table__.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    }
    operation_foreign_keys = {
        (
            tuple(constraint.columns.keys()),
            tuple(element.target_fullname for element in constraint.elements),
        )
        for constraint in EndpointOperation.__table__.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    }

    assert ("requested_by_service_client_id", "idempotency_key") in operation_uniques
    assert ("context_collection_id",) in operation_uniques
    assert ("command_id",) in operation_uniques
    assert ("id", "context_collection_id") in operation_uniques
    assert ("operation_id",) in collection_uniques
    assert ("operation_id", "id") in collection_uniques
    assert (
        ("id", "context_collection_id"),
        ("context_collections.operation_id", "context_collections.id"),
    ) in operation_foreign_keys
    assert (
        ("operation_id", "id"),
        ("endpoint_operations.id", "endpoint_operations.context_collection_id"),
    ) in collection_foreign_keys


@pytest.mark.asyncio
async def test_operation_collection_pointer_requires_reciprocal_collection_owner(
    session: AsyncSession,
) -> None:
    """A null collection owner must not bypass a non-null operation pointer."""
    client, device = await _ownership(session)
    operation_id = uuid4()
    collection = ContextCollection(
        id=uuid4(),
        created_at=NOW,
        device_id=device.id,
        profile="diagnostic_v1",
        requested_by=f"endpoint-operation:{client.id.hex}",
        idempotency_key="one-sided-collection",
        operation_id=None,
        status="requested",
        requested_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )
    operation = EndpointOperation(
        id=operation_id,
        created_at=NOW,
        requested_by_service_client_id=client.id,
        device_id=device.id,
        idempotency_key="one-sided-operation",
        capability="context.diagnostic.collect",
        parameters={"reason": "Reject one-sided ownership"},
        correlation=None,
        status="queued",
        deadline_at=NOW + timedelta(minutes=15),
        completed_at=None,
        context_collection_id=collection.id,
        command_id=None,
    )
    session.add_all((collection, operation))

    await session.flush()
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()
