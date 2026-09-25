"""Periodically report local sensor facts after the current WSS policy ACK."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.sensor_health import (
    PolicySensorHealthReportV1, SensorSourceStateV1,
)


@dataclass(frozen=True, slots=True)
class SensorHealthFacts:
    activity_listener_state: SensorSourceStateV1
    user_sensor_last_seen_at: datetime | None
    security_spool_state: SensorSourceStateV1
    usb_source_state: SensorSourceStateV1
    print_source_state: SensorSourceStateV1


class SensorHealthTransport(Protocol):
    async def send_sensor_health_report(
        self, report: PolicySensorHealthReportV1,
    ) -> None: ...


class SensorHealthRuntime:
    """Send facts only for the policy acknowledged on this WSS connection."""

    def __init__(
        self,
        *,
        policy_provider: Callable[[], EndpointPolicyV1 | None],
        fact_provider: Callable[[EndpointPolicyV1], Awaitable[SensorHealthFacts]],
        interval_seconds: float = 60.0,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("sensor health interval must be positive")
        self._policy_provider = policy_provider
        self._fact_provider = fact_provider
        self._interval_seconds = interval_seconds
        self._policy_ready = asyncio.Event()
        self._acknowledged_ref: tuple[UUID, int] | None = None

    def begin_connection(self) -> None:
        self._acknowledged_ref = None
        self._policy_ready.clear()

    def policy_ack_sent(self) -> None:
        policy = self._policy_provider()
        if policy is not None:
            self._acknowledged_ref = (policy.policy_id, policy.policy_version)
            self._policy_ready.set()

    async def send_once(
        self,
        transport: SensorHealthTransport,
        *,
        observed_at: datetime,
    ) -> bool:
        policy = self._policy_provider()
        if (
            not self._policy_ready.is_set()
            or policy is None
            or (policy.policy_id, policy.policy_version) != self._acknowledged_ref
        ):
            return False
        facts = await self._fact_provider(policy)
        current = self._policy_provider()
        if (
            current is None
            or current != policy
            or (current.policy_id, current.policy_version) != self._acknowledged_ref
        ):
            return False
        report = PolicySensorHealthReportV1(
            schema_version="policy_sensor_health_report_v1",
            observation_id=uuid4(), policy_id=policy.policy_id,
            policy_version=policy.policy_version, observed_at=observed_at,
            activity_listener_state=facts.activity_listener_state,
            user_sensor_last_seen_at=facts.user_sensor_last_seen_at,
            security_spool_state=facts.security_spool_state,
            usb_source_state=facts.usb_source_state,
            print_source_state=facts.print_source_state,
        )
        await transport.send_sensor_health_report(report)
        return True

    async def send_forever(
        self,
        transport: SensorHealthTransport,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        while True:
            await self._policy_ready.wait()
            await self.send_once(transport, observed_at=now())
            await sleep(self._interval_seconds)


__all__ = ["SensorHealthFacts", "SensorHealthRuntime"]
