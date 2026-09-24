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
from endpoint_contracts.system_process_primitives import (
    ProcessFindParametersV1,
    ProcessListParametersV1,
    SystemResourceSnapshotParametersV1,
)
from endpoint_contracts.service_printer_primitives import (
    PrinterListParametersV1,
    PrinterQueueSummaryParametersV1,
    PrinterStatusParametersV1,
    ServiceListParametersV1,
    ServiceStatusParametersV1 as ServiceStatusV2ParametersV1,
)
from endpoint_contracts.software_primitives import SoftwareFindParametersV1, SoftwareListParametersV1
from endpoint_contracts.filesystem_primitives import FileMetadataParametersV1, FreeSpaceParametersV1, PathExistsParametersV1
from endpoint_contracts.eventlog_primitives import EventQueryParametersV1, RecentErrorsParametersV1

from pc_agent.primitives.network.policy import AgentNetworkProbePolicy

from .handlers import adapter_list, route_get, service_status
from pc_agent.primitives.system_process.handlers import process_find, process_list, resource_snapshot
from pc_agent.primitives.service_printer.handlers import (
    printer_list, printer_queue_summary, printer_status, service_list,
    service_status as service_status_v2,
)
from pc_agent.primitives.software.handlers import software_find, software_list
from pc_agent.primitives.filesystem.handlers import file_metadata, free_space, path_exists
from pc_agent.primitives.eventlog.handlers import event_query, recent_errors


_READ_ONLY_COMMANDS: dict[str, tuple[str, type[Any], Callable[[Any], Any]]] = {
    "route.get": ("route_get_parameters_v1", RouteGetParametersV1, route_get),
    "adapter.list": ("adapter_list_parameters_v1", AdapterListParametersV1, adapter_list),
    "system.service_status": ("service_status_parameters_v1", ServiceStatusParametersV1, service_status),
    "system.resource_snapshot": ("system_resource_snapshot_parameters_v1", SystemResourceSnapshotParametersV1, resource_snapshot),
    "process.list": ("process_list_parameters_v1", ProcessListParametersV1, process_list),
    "process.find": ("process_find_parameters_v1", ProcessFindParametersV1, process_find),
    "service.list": ("service_list_parameters_v1", ServiceListParametersV1, service_list),
    "service.status": ("service_status_v2_parameters_v1", ServiceStatusV2ParametersV1, service_status_v2),
    "printer.list": ("printer_list_parameters_v1", PrinterListParametersV1, printer_list),
    "printer.status": ("printer_status_parameters_v1", PrinterStatusParametersV1, printer_status),
    "printer.queue.summary": ("printer_queue_summary_parameters_v1", PrinterQueueSummaryParametersV1, printer_queue_summary),
    "software.list": ("software_list_parameters_v1", SoftwareListParametersV1, software_list),
    "software.find": ("software_find_parameters_v1", SoftwareFindParametersV1, software_find),
    "filesystem.free_space": ("filesystem_free_space_parameters_v1", FreeSpaceParametersV1, free_space),
    "filesystem.path_exists": ("filesystem_path_exists_parameters_v1", PathExistsParametersV1, path_exists),
    "filesystem.file_metadata": ("filesystem_file_metadata_parameters_v1", FileMetadataParametersV1, file_metadata),
    "eventlog.query": ("eventlog_query_parameters_v1", EventQueryParametersV1, event_query),
    "eventlog.recent_errors": ("eventlog_recent_errors_parameters_v1", RecentErrorsParametersV1, recent_errors),
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
    schema_version, parameters_type, default_handler = registered
    try:
        parameters = parameters_type.model_validate(
            {"schema_version": schema_version, **command.parameters}
        )
    except ValidationError:
        return _failure(command, "read_only_capability_rejected", finished_at)
    if command.capability == "route.get":
        result = route_handler(parameters, policy=policy)
    elif command.capability == "adapter.list":
        result = adapter_handler(parameters)
    elif command.capability == "system.service_status":
        result = service_handler(parameters)
    else:
        result = default_handler(parameters)
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
