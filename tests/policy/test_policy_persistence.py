"""Policy versions and assignments remain unambiguous across devices."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.db.base import Base
import endpoint_server.db.models  # noqa: F401 - register foreign-key target tables
from endpoint_server.policy.models import (
    PolicyAssignment,
    PolicyDefinition,
    PolicyDeviceState,
    PolicyVersion,
)
from endpoint_server.policy.service import (
    PolicyMutationError,
    assign_default_policy,
    assign_device_policy,
    create_policy_version,
    resolve_effective_policy,
)
from tests.contracts.test_endpoint_policy_v1 import POLICY_ID, _policy


@pytest.fixture
async def sessions():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=[
            PolicyDefinition.__table__, PolicyVersion.__table__,
            PolicyAssignment.__table__, PolicyDeviceState.__table__,
        ]))
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.mark.asyncio
async def test_new_policy_version_is_immutable_and_digest_bound(sessions) -> None:
    async with sessions() as session:
        definition = PolicyDefinition(id=POLICY_ID, name="Municipal Default")
        session.add(definition)
        await session.flush()
        version = await create_policy_version(session, definition.id, _policy(), actor_id=uuid4())
        assert version.version == 1
        assert len(version.digest) == 64
        await session.commit()

    async with sessions() as session:
        stored = await session.scalar(select(PolicyVersion).where(PolicyVersion.definition_id == POLICY_ID))
        assert stored is not None
        stored.document = {**stored.document, "policy_version": 2}
        with pytest.raises(PolicyMutationError):
            await session.commit()


@pytest.mark.asyncio
async def test_duplicate_version_is_rejected_by_database(sessions) -> None:
    async with sessions() as session:
        session.add(PolicyDefinition(id=POLICY_ID, name="Municipal Default"))
        await session.flush()
        await create_policy_version(session, POLICY_ID, _policy(), actor_id=uuid4())
        await session.commit()
    async with sessions() as session:
        session.add(PolicyVersion(
            definition_id=POLICY_ID,
            version=1,
            digest="0" * 64,
            document=_policy(),
            created_by=uuid4(),
        ))
        with pytest.raises(IntegrityError):
            await session.commit()


@pytest.mark.asyncio
async def test_device_override_takes_precedence_over_default(sessions) -> None:
    device_id = UUID("d7000000-0000-4000-8000-000000000002")
    other_device_id = UUID("d7000000-0000-4000-8000-000000000003")
    async with sessions() as session:
        session.add(PolicyDefinition(id=POLICY_ID, name="Municipal Default"))
        await session.flush()
        first = await create_policy_version(session, POLICY_ID, _policy(), actor_id=uuid4())
        second = await create_policy_version(
            session, POLICY_ID, _policy(policy_version=2), actor_id=uuid4(),
        )
        await assign_default_policy(session, first.id, actor_id=uuid4())
        await assign_device_policy(session, device_id, second.id, actor_id=uuid4())
        await session.commit()
    async with sessions() as session:
        assert (await resolve_effective_policy(session, device_id)).id == second.id
        assert (await resolve_effective_policy(session, other_device_id)).id == first.id


@pytest.mark.asyncio
async def test_second_default_assignment_replaces_only_the_default(sessions) -> None:
    device_id = uuid4()
    async with sessions() as session:
        session.add(PolicyDefinition(id=POLICY_ID, name="Municipal Default"))
        await session.flush()
        first = await create_policy_version(session, POLICY_ID, _policy(), actor_id=uuid4())
        second = await create_policy_version(session, POLICY_ID, _policy(policy_version=2), actor_id=uuid4())
        await assign_default_policy(session, first.id, actor_id=uuid4())
        await assign_device_policy(session, device_id, first.id, actor_id=uuid4())
        await assign_default_policy(session, second.id, actor_id=uuid4())
        await session.commit()
    async with sessions() as session:
        assert (await resolve_effective_policy(session, uuid4())).id == second.id
        assert (await resolve_effective_policy(session, device_id)).id == first.id
