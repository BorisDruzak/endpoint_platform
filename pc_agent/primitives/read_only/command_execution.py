"""Map fixed read-only Gateway capabilities to closed platform adapters."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from endpoint_contracts import AgentCommandV1, AgentResultV1
from endpoint_contracts.read_only_primitives import (
    AdapterListParametersV1,
    AdapterListResultV1,
    RouteGetParametersV1,
    RouteGetResultV1,
    ServiceStatusParametersV1,
    ServiceStatusResultV1,
)

from pc_agent.primitives.network.policy import AgentNetworkProbePolicy

from .handlers import adapter_list, route_get, service_status


_READ_ONLY_COMMANDS: dict[str, tuple[str, type[Any], Callable[[Any], Any]]] = {
    "route.get": ("route_get_parameters_v1", RouteGetParametersV1, route_get),
    "adapter.list": ("adapter_list_parameters_v1", AdapterListParametersV1, adapter_list),
    "system.service_status": ("service_status_parameters_v1", ServiceStatusParametersV1, service_status),
}


def execute_read_only_agent_command(
    command: AgentCommandV1,
    *,
    policy: AgentNetworkProbePolicy,
    route_handler: Callable[..., RouteGetResultV1] = route_get,
    adapter_handler: Callable[[AdapterListParametersV1], AdapterListResultV1] = adapter_list,
    service_handler: Callable[[ServiceStatusParametersV1], ServiceStatusResultV1] = service_status,
    completed_at: datetime | None = None,
) -> AgentResultV1:
    """Run one closed primitive; no caller chooses code, executable, path, or service."""
    finished_at = completed_at or datetime.now(UTC)
    registered = _READ_ONLY_COMMANDS.get(command.capability)
    if registered is None:
        return _failure(command, "read_only_capability_rejected", finished_at)
    schema_version, parameters_type, _default_handler = registered
    handlers: dict[str, Callable[[Any], Any]] = {
        "route.get": route_handler,
        "adapter.list": adapter_handler,
        "system.service_status": service_handler,
    }
    try:
        parameters = parameters_type.model_validate(
            {"schema_version": schema_version, **command.parameters}
        )
    except ValidationError:
        return _failure(command, "read_only_capability_rejected", finished_at)
    if command.capability == "route.get":
        result = route_handler(parameters, policy=policy)
    else:
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
        message=result.error_code or "read_only_primitive_failed",
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


__all__ = ["execute_read_only_agent_command"]
