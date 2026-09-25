"""Negotiate Endpoint Policy independently of Gateway command capabilities."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.gateway_ws import (
    AgentHelloV1,
    EndpointPolicyAckV1,
    EndpointPolicyDeliveryEnvelopeV1,
    EndpointPolicyDeliveryV1,
)

from .models import PolicyApplication, PolicyDeviceState, PolicyVersion
from .service import resolve_effective_policy


_MINIMUM_AGENT_VERSION = (3, 2, 68)
_VERSION = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)$")


class PolicyAcknowledgementRejected(ValueError):
    """The acknowledgement does not match the delivered effective policy."""


def supports_endpoint_policy(hello: AgentHelloV1) -> bool:
    """Do not send new frames to older or non-Windows Agents."""
    match = _VERSION.fullmatch(hello.agent_version)
    return (
        hello.platform == "windows_amd64"
        and "endpoint.policy.v1" in hello.protocol_features
        and match is not None
        and tuple(int(part) for part in match.groups()) >= _MINIMUM_AGENT_VERSION
    )


async def _state_for_update(session: AsyncSession, device_id: UUID) -> PolicyDeviceState:
    state = await session.scalar(
        select(PolicyDeviceState)
        .where(PolicyDeviceState.device_id == device_id)
        .with_for_update()
    )
    if state is None:
        state = PolicyDeviceState(device_id=device_id, status="PENDING")
        session.add(state)
    return state


async def prepare_policy_delivery(
    session: AsyncSession,
    hello: AgentHelloV1,
    *,
    only_if_changed: bool = False,
) -> EndpointPolicyDeliveryEnvelopeV1 | None:
    """Record requested state and construct one validated frame for a new session."""
    version = await resolve_effective_policy(session, hello.device_id)
    if version is None:
        return None
    state = await _state_for_update(session, hello.device_id)
    if (
        only_if_changed
        and state.policy_version_id == version.id
        and state.policy_digest == version.digest
        and state.status in {"APPLIED", "ERROR", "UNSUPPORTED"}
    ):
        return None
    state.policy_version_id = version.id
    state.policy_digest = version.digest
    state.error_code = None
    state.received_at = None
    state.applied_at = None
    state.acknowledged_at = None
    if not supports_endpoint_policy(hello):
        state.status = "UNSUPPORTED"
        await session.flush()
        return None
    state.status = "PENDING"
    policy = EndpointPolicyV1.model_validate(version.document)
    delivery = EndpointPolicyDeliveryEnvelopeV1(
        schema_version="gateway_ws_envelope_v1",
        kind="endpoint_policy_delivery",
        sequence=0,
        payload=EndpointPolicyDeliveryV1(
            schema_version="endpoint_policy_delivery_v1",
            policy_version_id=version.id,
            policy=policy,
            policy_digest=version.digest,
            issued_at=datetime.now(UTC),
        ),
    )
    await session.flush()
    return delivery


async def record_policy_ack(
    session: AsyncSession,
    device_id: UUID,
    ack: EndpointPolicyAckV1,
) -> PolicyDeviceState:
    """Accept an ACK only for a delivered version; mark superseded ACKs stale."""
    state = await session.scalar(
        select(PolicyDeviceState)
        .where(PolicyDeviceState.device_id == device_id)
        .with_for_update()
    )
    if state is None or state.policy_version_id is None:
        raise PolicyAcknowledgementRejected("policy acknowledgement has no pending delivery")
    delivered = await session.get(PolicyVersion, state.policy_version_id)
    if (
        delivered is None
        or state.policy_digest != delivered.digest
        or ack.policy_id != delivered.definition_id
        or ack.policy_version != delivered.version
        or ack.policy_digest != delivered.digest
        or state.status not in {"PENDING", "APPLIED", "ERROR", "STALE"}
    ):
        raise PolicyAcknowledgementRejected("policy acknowledgement does not match delivery")
    effective = await resolve_effective_policy(session, device_id)
    superseded = effective is None or effective.id != delivered.id
    state.status = "STALE" if superseded else ack.status
    state.error_code = "SUPERSEDED" if superseded else ack.error_code
    state.received_at = ack.received_at
    state.applied_at = ack.applied_at
    acknowledged_at = datetime.now(UTC)
    state.acknowledged_at = acknowledged_at
    if ack.status == "APPLIED" and ack.applied_at is not None:
        applied_at = ack.applied_at.astimezone(UTC)
        application = await session.scalar(
            select(PolicyApplication).where(
                PolicyApplication.device_id == device_id,
                PolicyApplication.policy_version_id == delivered.id,
                PolicyApplication.applied_at == applied_at,
            )
        )
        if application is None:
            session.add(PolicyApplication(
                device_id=device_id,
                policy_version_id=delivered.id,
                policy_digest=delivered.digest,
                applied_at=applied_at,
                acknowledged_at=acknowledged_at,
            ))
        elif application.policy_digest != delivered.digest:
            raise PolicyAcknowledgementRejected("applied policy history conflicts")
    await session.flush()
    return state
