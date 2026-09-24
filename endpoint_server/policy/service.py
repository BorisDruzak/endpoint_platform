"""Create immutable policy versions and resolve device assignments."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest

from .models import PolicyAssignment, PolicyDefinition, PolicyMutationError, PolicyVersion


class PolicyNotFound(ValueError):
    """The requested definition or version does not exist."""


async def create_policy_version(
    session: AsyncSession,
    definition_id: UUID,
    document: EndpointPolicyV1 | dict[str, object],
    *,
    actor_id: UUID,
) -> PolicyVersion:
    """Append only the next version while holding the definition row lock."""
    definition = await session.get(PolicyDefinition, definition_id, with_for_update=True)
    if definition is None:
        raise PolicyNotFound("policy definition not found")
    policy = (
        document
        if isinstance(document, EndpointPolicyV1)
        else EndpointPolicyV1.model_validate(document)
    )
    if policy.policy_id != definition_id:
        raise ValueError("policy document id does not match definition")
    latest = await session.scalar(
        select(func.max(PolicyVersion.version)).where(
            PolicyVersion.definition_id == definition_id
        )
    )
    if policy.policy_version != (latest or 0) + 1:
        raise ValueError("policy version must increment by one")
    version = PolicyVersion(
        definition_id=definition_id,
        version=policy.policy_version,
        digest=policy_digest(policy),
        document=policy.model_dump(mode="json"),
        created_by=actor_id,
    )
    session.add(version)
    await session.flush()
    return version


async def _require_version(session: AsyncSession, version_id: UUID) -> PolicyVersion:
    version = await session.get(PolicyVersion, version_id)
    if version is None:
        raise PolicyNotFound("policy version not found")
    return version


async def assign_default_policy(
    session: AsyncSession, version_id: UUID, *, actor_id: UUID
) -> PolicyAssignment:
    await _require_version(session, version_id)
    assignment = await session.scalar(
        select(PolicyAssignment)
        .where(PolicyAssignment.scope == "default")
        .with_for_update()
    )
    if assignment is None:
        assignment = PolicyAssignment(scope="default", device_id=None)
        session.add(assignment)
    assignment.policy_version_id = version_id
    assignment.assigned_by = actor_id
    assignment.assigned_at = datetime.now(UTC)
    await session.flush()
    return assignment


async def assign_device_policy(
    session: AsyncSession, device_id: UUID, version_id: UUID, *, actor_id: UUID
) -> PolicyAssignment:
    await _require_version(session, version_id)
    assignment = await session.scalar(
        select(PolicyAssignment)
        .where(PolicyAssignment.scope == "device", PolicyAssignment.device_id == device_id)
        .with_for_update()
    )
    if assignment is None:
        assignment = PolicyAssignment(scope="device", device_id=device_id)
        session.add(assignment)
    assignment.policy_version_id = version_id
    assignment.assigned_by = actor_id
    assignment.assigned_at = datetime.now(UTC)
    await session.flush()
    return assignment


async def resolve_effective_policy(
    session: AsyncSession, device_id: UUID
) -> PolicyVersion | None:
    assignment = await session.scalar(
        select(PolicyAssignment).where(
            PolicyAssignment.scope == "device", PolicyAssignment.device_id == device_id
        )
    )
    if assignment is None:
        assignment = await session.scalar(
            select(PolicyAssignment).where(PolicyAssignment.scope == "default")
        )
    return (
        await session.get(PolicyVersion, assignment.policy_version_id)
        if assignment is not None
        else None
    )


__all__ = [
    "PolicyMutationError",
    "PolicyNotFound",
    "assign_default_policy",
    "assign_device_policy",
    "create_policy_version",
    "resolve_effective_policy",
]
