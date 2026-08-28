"""Opt-in PostgreSQL constraints and concurrency coverage for operations."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_contracts import EndpointOperationCreateV1
from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.migrations.runtime_config import configure_database_url
from endpoint_server.db.models import (
    AuditEvent,
    Device,
    EndpointOperation,
    ModuleDefinition,
    ModuleVersion,
    ServiceClient,
)
from endpoint_server.modules.operation_service import (
    ModuleOperationConflict,
    create_module_parent_operation,
)
from endpoint_server.operations.service import (
    OperationConflict,
    create_operation_outcome,
    expire_operations,
)
from endpoint_server.policy.network_targets import NetworkTargetPolicyV1


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


async def _execute(database_url: str, statement: str) -> None:
    connection = await asyncpg.connect(database_url)
    try:
        await connection.execute(statement)
    finally:
        await connection.close()


def _upgrade_disposable_database(
    database_url: str,
    *,
    expected_database_name: str,
) -> None:
    """Run Alembic only while its ambient URL names the random test database."""
    parsed = make_url(database_url)
    prefix = "endpoint_operations_"
    suffix = expected_database_name.removeprefix(prefix)
    if (
        parsed.get_backend_name() != "postgresql"
        or parsed.host not in {"127.0.0.1", "localhost", "::1"}
        or bool(parsed.query)
        or parsed.database != expected_database_name
        or not expected_database_name.startswith(prefix)
        or len(suffix) != 32
        or any(character not in "0123456789abcdef" for character in suffix)
    ):
        raise ValueError(
            "Alembic target must be the expected random loopback operation database"
        )

    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with pytest.MonkeyPatch.context() as migration_environment:
        migration_environment.setenv("DATABASE_URL", database_url)
        command.upgrade(config, "head")


def test_disposable_migration_target_overrides_ambient_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Alembic env.py must only see the validated random loopback database."""
    ambient_url = "postgresql+asyncpg://ambient@production.invalid/endpoint"
    database_name = "endpoint_operations_0123456789abcdef0123456789abcdef"
    disposable_url = f"postgresql+asyncpg://local@127.0.0.1/{database_name}"
    observed: dict[str, str] = {}
    monkeypatch.setenv("DATABASE_URL", ambient_url)

    def fake_upgrade(config: Config, revision: str) -> None:
        observed["revision"] = revision
        observed["database_url"] = configure_database_url(config, os.environ)

    monkeypatch.setattr(command, "upgrade", fake_upgrade)

    _upgrade_disposable_database(
        disposable_url,
        expected_database_name=database_name,
    )

    assert observed == {
        "revision": "head",
        "database_url": disposable_url,
    }
    assert os.environ["DATABASE_URL"] == ambient_url


def test_fixture_rejects_query_target_override_before_database_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """asyncpg query fields must not redirect setup away from loopback."""
    calls: list[str] = []
    monkeypatch.setenv(
        "ENDPOINT_TEST_POSTGRES_URL",
        "postgresql+asyncpg://local@127.0.0.1/postgres"
        "?host=production.invalid&database=production",
    )

    async def unexpected_execute(database_url: str, statement: str) -> None:
        calls.append(f"connection:{database_url}:{statement}")

    def unexpected_upgrade(config: Config, revision: str) -> None:
        calls.append(f"migration:{revision}")

    monkeypatch.setitem(globals(), "_execute", unexpected_execute)
    monkeypatch.setattr(command, "upgrade", unexpected_upgrade)
    fixture_body = operation_database_url.__wrapped__

    with pytest.raises(ValueError, match="query parameters"):
        next(fixture_body())

    assert calls == []


@pytest.fixture(scope="module")
def operation_database_url() -> Iterator[str]:
    """Create a disposable loopback database migrated through the real head."""
    admin_url = os.environ.get("ENDPOINT_TEST_POSTGRES_URL")
    if not admin_url:
        pytest.skip(
            "set ENDPOINT_TEST_POSTGRES_URL to a disposable local PostgreSQL server"
        )
    parsed = make_url(admin_url)
    if parsed.query:
        raise ValueError(
            "ENDPOINT_TEST_POSTGRES_URL must not contain query parameters"
        )
    if parsed.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("operation tests may only use a loopback PostgreSQL server")
    plain_admin_url = parsed.set(drivername="postgresql", query={}).render_as_string(
        hide_password=False
    )
    database_name = f"endpoint_operations_{uuid4().hex}"
    asyncio.run(_execute(plain_admin_url, f'CREATE DATABASE "{database_name}"'))
    database_url = parsed.set(
        drivername="postgresql+asyncpg",
        database=database_name,
        query={},
    ).render_as_string(hide_password=False)
    try:
        _upgrade_disposable_database(
            database_url,
            expected_database_name=database_name,
        )
        yield database_url
    finally:
        asyncio.run(
            _execute(
                plain_admin_url,
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{database_name}' AND pid <> pg_backend_pid()",
            )
        )
        asyncio.run(_execute(plain_admin_url, f'DROP DATABASE "{database_name}"'))


def _request(
    *,
    reason: str = "Collect PostgreSQL diagnostic context",
) -> EndpointOperationCreateV1:
    return EndpointOperationCreateV1.model_validate(
        {
            "schema_version": "endpoint_operation_create_v1",
            "capability": "context.diagnostic.collect",
            "parameters": {"reason": reason},
        }
    )


def _module_recipe() -> EndpointRecipeModuleSpecV1:
    return EndpointRecipeModuleSpecV1.model_validate(
        {
            "schema_version": "endpoint_recipe_module_v1",
            "module_key": "network.postgres.race",
            "supported_platforms": ["linux_amd64"],
            "inputs": [{"name": "target", "value_type": "string"}],
            "steps": [
                {
                    "step_id": "dns",
                    "capability": "dns.resolve",
                    "parameters": {
                        "target": {"kind": "input", "name": "target"},
                        "family": {"kind": "literal", "value": "any"},
                    },
                }
            ],
        }
    )


async def _ownership(
    session: AsyncSession,
    *,
    client_identifier: str,
) -> tuple[ServiceClient, Device]:
    client = ServiceClient(
        id=uuid4(),
        client_identifier=client_identifier,
        display_name="PostgreSQL operation client",
    )
    device = Device(
        id=uuid4(),
        device_identifier=f"operation-pg-{uuid4().hex}",
        display_name="PostgreSQL endpoint",
        retired_at=None,
    )
    session.add_all((client, device))
    await session.flush()
    return client, device


@pytest.mark.asyncio
async def test_deferred_operation_collection_pair_commits_atomically_in_postgresql(
    operation_database_url: str,
) -> None:
    engine = create_async_engine(operation_database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            client, device = await _ownership(
                session,
                client_identifier=f"operation-deferred-{uuid4().hex}",
            )
            operation, created = await create_operation_outcome(
                session,
                request=_request(),
                service_client_id=client.id,
                device_id=device.id,
                idempotency_key="postgres-deferred-pair",
                now=NOW,
            )
            await session.commit()

        async with factory() as session:
            persisted = await session.get(EndpointOperation, operation.id)
            collection = await session.scalar(
                select(ContextCollection).where(
                    ContextCollection.operation_id == operation.id
                )
            )
            audits = (
                await session.scalars(
                    select(AuditEvent).where(
                        AuditEvent.object_identifier == str(operation.id),
                        AuditEvent.action == "endpoint.operation_created",
                    )
                )
            ).all()
        assert created is True
        assert persisted is not None
        assert collection is not None
        assert persisted.context_collection_id == collection.id
        assert collection.operation_id == persisted.id
        assert len(audits) == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_same_client_key_concurrency_replays_and_conflicts_in_postgresql(
    operation_database_url: str,
) -> None:
    engine = create_async_engine(operation_database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    key = f"postgres-race-{uuid4().hex}"
    request = _request()
    try:
        async with factory() as session:
            client, device = await _ownership(
                session,
                client_identifier=f"operation-race-{uuid4().hex}",
            )
            await session.commit()

        async def create() -> tuple[object, bool]:
            async with factory() as session:
                operation, created = await create_operation_outcome(
                    session,
                    request=request,
                    service_client_id=client.id,
                    device_id=device.id,
                    idempotency_key=key,
                    now=NOW,
                )
                await session.commit()
                return operation.id, created

        outcomes = await asyncio.gather(create(), create())
        assert {operation_id for operation_id, _ in outcomes} == {outcomes[0][0]}
        assert sorted(created for _, created in outcomes) == [False, True]

        async with factory() as session:
            replay, replayed = await create_operation_outcome(
                session,
                request=request,
                service_client_id=client.id,
                device_id=device.id,
                idempotency_key=key,
                now=NOW + timedelta(seconds=1),
            )
            await session.commit()
        assert replayed is False
        assert replay.id == outcomes[0][0]

        async with factory() as session:
            with pytest.raises(OperationConflict) as rejected:
                await create_operation_outcome(
                    session,
                    request=_request(reason="Different normalized PostgreSQL payload"),
                    service_client_id=client.id,
                    device_id=device.id,
                    idempotency_key=key,
                    now=NOW + timedelta(seconds=2),
                )
            await session.rollback()
        assert rejected.value.code == "endpoint_operation_idempotency_conflict"

        async with factory() as session:
            operations = (
                await session.scalars(
                    select(EndpointOperation).where(
                        EndpointOperation.requested_by_service_client_id == client.id,
                        EndpointOperation.idempotency_key == key,
                    )
                )
            ).all()
        assert len(operations) == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_module_same_key_concurrency_replays_and_conflicts_in_postgresql(
    operation_database_url: str,
) -> None:
    """Concurrent module creation has the same single-owner idempotency boundary."""
    engine = create_async_engine(operation_database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    key = f"module-postgres-race-{uuid4().hex}"
    recipe = _module_recipe()
    policy = NetworkTargetPolicyV1.from_values(
        allowed_cidrs=[], allowed_suffixes=[".example.test"]
    )
    try:
        async with factory() as session:
            client, device = await _ownership(
                session,
                client_identifier=f"module-race-{uuid4().hex}",
            )
            definition = ModuleDefinition(
                id=uuid4(), module_key=recipe.module_key, display_name="Module race"
            )
            version = ModuleVersion(
                id=uuid4(),
                module_definition_id=definition.id,
                version="1.0.0",
                recipe=recipe.model_dump(mode="json"),
                state="published",
            )
            session.add_all((definition, version))
            await session.commit()

        async def create() -> tuple[object, bool]:
            async with factory() as session:
                operation, created = await create_module_parent_operation(
                    session,
                    service_client_id=client.id,
                    device_id=device.id,
                    module_key=recipe.module_key,
                    version="1.0.0",
                    inputs={"target": "api.example.test"},
                    idempotency_key=key,
                    network_policy=policy,
                    now=NOW,
                )
                await session.commit()
                return operation.id, created

        outcomes = await asyncio.gather(create(), create())
        assert {operation_id for operation_id, _ in outcomes} == {outcomes[0][0]}
        assert sorted(created for _, created in outcomes) == [False, True]

        async with factory() as session:
            with pytest.raises(ModuleOperationConflict) as rejected:
                await create_module_parent_operation(
                    session,
                    service_client_id=client.id,
                    device_id=device.id,
                    module_key=recipe.module_key,
                    version="1.0.0",
                    inputs={"target": "different.example.test"},
                    idempotency_key=key,
                    network_policy=policy,
                    now=NOW + timedelta(seconds=1),
                )
            await session.rollback()
        assert rejected.value.code == "endpoint_module_operation_idempotency_conflict"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_postgresql_rejects_operation_pointer_without_collection_reciprocity(
    operation_database_url: str,
) -> None:
    engine = create_async_engine(operation_database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            client, device = await _ownership(
                session,
                client_identifier=f"operation-null-pair-{uuid4().hex}",
            )
            operation_id = uuid4()
            collection = ContextCollection(
                id=uuid4(),
                created_at=NOW,
                device_id=device.id,
                profile="diagnostic_v1",
                requested_by=f"endpoint-operation:{client.id.hex}",
                idempotency_key=f"null-pair-{uuid4().hex}",
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
                idempotency_key=f"null-operation-{uuid4().hex}",
                capability="context.diagnostic.collect",
                parameters={"reason": "Reject null PostgreSQL reciprocity"},
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
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_expiry_skips_locked_operation_then_finishes_after_release_in_postgresql(
    operation_database_url: str,
) -> None:
    engine = create_async_engine(operation_database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            client, device = await _ownership(
                session,
                client_identifier=f"operation-expiry-{uuid4().hex}",
            )
            first, _ = await create_operation_outcome(
                session,
                request=_request(),
                service_client_id=client.id,
                device_id=device.id,
                idempotency_key=f"expiry-first-{uuid4().hex}",
                now=NOW,
            )
            second, _ = await create_operation_outcome(
                session,
                request=_request(),
                service_client_id=client.id,
                device_id=device.id,
                idempotency_key=f"expiry-second-{uuid4().hex}",
                now=NOW,
            )
            await session.commit()

        holder = factory()
        try:
            locked = await holder.scalar(
                select(EndpointOperation)
                .where(EndpointOperation.id == first.id)
                .with_for_update()
            )
            assert locked is not None
            async with factory() as expiration_session:
                assert await expire_operations(
                    expiration_session,
                    now=NOW + timedelta(minutes=15),
                    limit=10,
                ) == 1
                await expiration_session.commit()
            await holder.rollback()
        finally:
            if holder.in_transaction():
                await holder.rollback()
            await holder.close()

        async with factory() as expiration_session:
            assert await expire_operations(
                expiration_session,
                now=NOW + timedelta(minutes=15, seconds=1),
                limit=10,
            ) == 1
            await expiration_session.commit()

        async with factory() as session:
            statuses = {
                operation.id: operation.status
                for operation in (
                    await session.scalars(
                        select(EndpointOperation).where(
                            EndpointOperation.id.in_((first.id, second.id))
                        )
                    )
                ).all()
            }
        assert statuses == {first.id: "expired", second.id: "expired"}
    finally:
        await engine.dispose()
