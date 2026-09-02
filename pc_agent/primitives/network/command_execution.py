"""Map fixed Gateway capabilities to policy-checked network primitives."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from endpoint_contracts import AgentCommandV1, AgentResultV1
from endpoint_contracts.network_primitives import (
    DnsResolveParametersV1,
    DnsResolveResultV1,
    NetworkPingParametersV1,
    NetworkPingResultV1,
    TcpConnectParametersV1,
    TcpConnectResultV1,
)

from .handlers import ping_host, resolve_dns, tcp_connect
from .policy import AgentNetworkProbePolicy, NetworkProbeDenied


_NETWORK_COMMANDS: dict[
    str,
    tuple[str, type[Any], Callable[[Any], Any]],
] = {
    "dns.resolve": ("dns_resolve_parameters_v1", DnsResolveParametersV1, resolve_dns),
    "network.ping": ("network_ping_parameters_v1", NetworkPingParametersV1, ping_host),
    "tcp.connect": ("tcp_connect_parameters_v1", TcpConnectParametersV1, tcp_connect),
}


def execute_network_agent_command(
    command: AgentCommandV1,
    *,
    policy: AgentNetworkProbePolicy,
    dns_handler: Callable[[DnsResolveParametersV1], DnsResolveResultV1] = resolve_dns,
    ping_handler: Callable[[NetworkPingParametersV1], NetworkPingResultV1] = ping_host,
    tcp_handler: Callable[[TcpConnectParametersV1], TcpConnectResultV1] = tcp_connect,
    completed_at: datetime | None = None,
) -> AgentResultV1:
    """Execute one network command without permitting runtime-selected code."""
    finished_at = completed_at or datetime.now(UTC)
    registered = _NETWORK_COMMANDS.get(command.capability)
    if registered is None:
        return _failure(command, "network_capability_rejected", finished_at)
    schema_version, parameters_type, _default_handler = registered
    handlers: dict[str, Callable[[Any], Any]] = {
        "dns.resolve": dns_handler,
        "network.ping": ping_handler,
        "tcp.connect": tcp_handler,
    }
    try:
        parameters = parameters_type.model_validate(
            {"schema_version": schema_version, **command.parameters}
        )
        policy.require_allowed(parameters.target)
    except NetworkProbeDenied as error:
        return _failure(command, str(error), finished_at)
    except ValidationError:
        return _failure(command, "network_capability_rejected", finished_at)
    result = handlers[command.capability](parameters)
    result_payload = result.model_dump(mode="json")
    if result.status == "succeeded":
        return AgentResultV1(
            schema_version="agent_result_v1",
            command_id=command.command_id,
            device_id=command.device_id,
            status="succeeded",
            result_items=[result_payload],
            completed_at=finished_at,
        )
    return AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command.command_id,
        device_id=command.device_id,
        status="failed",
        result_items=[result_payload],
        message=result.error_code or "network_probe_failed",
        completed_at=finished_at,
    )


def _failure(command: AgentCommandV1, message: str, completed_at: datetime) -> AgentResultV1:
    return AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command.command_id,
        device_id=command.device_id,
        status="failed",
        result_items=[],
        message=message,
        completed_at=completed_at,
    )


__all__ = ["execute_network_agent_command"]
