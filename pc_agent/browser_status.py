"""Shared browser status projection and Policy-ACK-gated delivery."""
from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Awaitable, Callable, Literal, Mapping, Protocol
from uuid import UUID, uuid4
from endpoint_contracts.browser_status import BrowserFamilyStatusV1, BrowserStatusReportV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.activity_ingress import BrowserHeartbeatFact

_LOG = logging.getLogger(__name__)
BrowserFamily = Literal["chrome", "yandex"]
PolicyOwner = Literal["ENDPOINT", "EXTERNAL", "NONE", "CONFLICT", "UNKNOWN"]
PolicyState = Literal["APPLIED", "NOT_APPLIED", "CONFLICT", "UNKNOWN"]

@dataclass(frozen=True, slots=True)
class BrowserHostFacts:
    browser_state: Literal["DETECTED", "ABSENT", "UNKNOWN"]
    running_state: Literal["RUNNING", "CLOSED", "UNKNOWN"]
    policy_owner: PolicyOwner
    installation_policy_state: PolicyState
    native_host_state: Literal["READY", "MISSING", "UNKNOWN"]
    last_running_at: datetime | None



class BrowserHeartbeatSource(Protocol):
    def latest_heartbeats(
        self, policy: EndpointPolicyV1,
    ) -> dict[str, BrowserHeartbeatFact]: ...


class BrowserStatusTransport(Protocol):
    async def send_browser_status_report(self, report: BrowserStatusReportV1) -> None: ...


class BrowserHostProbe(Protocol):
    def collect(self, *, observed_at: datetime) -> dict[BrowserFamily, BrowserHostFacts]: ...


class BrowserStatusRuntime:
    """Send a current two-family snapshot periodically after a policy ACK."""

    def __init__(
        self,
        *,
        policy_provider: Callable[[], EndpointPolicyV1 | None],
        ingress: BrowserHeartbeatSource,
        probe: BrowserHostProbe,
        interval_seconds: float = 60.0,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("browser status interval must be positive")
        self._policy_provider = policy_provider
        self._ingress = ingress
        self._probe = probe
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

    async def send_forever(
        self,
        transport: BrowserStatusTransport,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        while True:
            await self._policy_ready.wait()
            policy = self._policy_provider()
            if (
                policy is None
                or (policy.policy_id, policy.policy_version) != self._acknowledged_ref
            ):
                await sleep(min(1.0, self._interval_seconds))
                continue
            observed_at = now()
            try:
                hosts = await asyncio.to_thread(self._probe.collect, observed_at=observed_at)
                heartbeats = self._ingress.latest_heartbeats(policy)
                report = build_browser_status_report(
                    policy, hosts, heartbeats, observed_at=observed_at,
                )
            except Exception:
                _LOG.warning("browser status collection unavailable")
                await sleep(self._interval_seconds)
                continue
            current = self._policy_provider()
            if (
                current is not None
                and (current.policy_id, current.policy_version) == self._acknowledged_ref
                and current == policy
            ):
                await transport.send_browser_status_report(report)
            await sleep(self._interval_seconds)


def build_browser_status_report(
    policy: EndpointPolicyV1,
    hosts: Mapping[BrowserFamily, BrowserHostFacts],
    heartbeats: Mapping[str, BrowserHeartbeatFact],
    *,
    observed_at: datetime,
) -> BrowserStatusReportV1:
    """Create one two-family report without browser content or Agent compliance."""
    browsers = []
    for family in ("chrome", "yandex"):
        host = hosts[family]
        heartbeat = heartbeats.get(family)
        browsers.append(BrowserFamilyStatusV1(
            browser_family=family,
            browser_state=host.browser_state,
            running_state=host.running_state,
            policy_owner=host.policy_owner,
            installation_policy_state=host.installation_policy_state,
            native_host_state=host.native_host_state,
            extension_version=heartbeat.extension_version if heartbeat else None,
            extension_last_seen_at=heartbeat.last_seen_at if heartbeat else None,
            extension_install_type=(
                "ADMIN" if heartbeat.install_type == "admin"
                else "UNKNOWN" if heartbeat.install_type == "unknown"
                else "OTHER"
            ) if heartbeat else "UNKNOWN",
            last_running_at=host.last_running_at,
        ))
    return BrowserStatusReportV1(
        schema_version="browser_status_report_v1",
        observation_id=uuid4(), policy_id=policy.policy_id,
        policy_version=policy.policy_version, observed_at=observed_at,
        browsers=browsers,
    )
