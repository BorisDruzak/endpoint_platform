"""Closed, typed module-capability registry owned by Endpoint Platform."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Literal

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from .base import ContractModelV1
from .network_primitives import (
    DnsResolveParametersV1,
    DnsResolveResultV1,
    NetworkPingParametersV1,
    NetworkPingResultV1,
    TcpConnectParametersV1,
    TcpConnectResultV1,
)
from .read_only_primitives import (
    AdapterListParametersV1,
    AdapterListResultV1,
    RouteGetParametersV1,
    RouteGetResultV1,
    ServiceStatusParametersV1,
    ServiceStatusResultV1,
)
from .system_process_primitives import (
    ProcessFindParametersV1,
    ProcessFindResultV1,
    ProcessListParametersV1,
    ProcessListResultV1,
    SystemResourceSnapshotParametersV1,
    SystemResourceSnapshotResultV1,
)
from .service_printer_primitives import (
    PrinterListParametersV1,
    PrinterListResultV1,
    PrinterQueueSummaryParametersV1,
    PrinterQueueSummaryResultV1,
    PrinterStatusParametersV1,
    PrinterStatusResultV1,
    ServiceListParametersV1,
    ServiceListResultV1,
    ServiceStatusParametersV1 as ServiceStatusV2ParametersV1,
    ServiceStatusResultV1 as ServiceStatusV2ResultV1,
)
from .software_primitives import (
    SoftwareFindParametersV1,
    SoftwareFindResultV1,
    SoftwareListParametersV1,
    SoftwareListResultV1,
)
from .filesystem_primitives import (
    FileMetadataParametersV1,
    FileMetadataResultV1,
    FreeSpaceParametersV1,
    FreeSpaceResultV1,
    PathExistsParametersV1,
    PathExistsResultV1,
)
from .eventlog_primitives import (
    EventQueryParametersV1,
    EventQueryResultV1,
    RecentErrorsParametersV1,
    RecentErrorsResultV1,
)


ModuleCapabilityNameV1 = Literal[
    "dns.resolve",
    "network.ping",
    "tcp.connect",
    "route.get",
    "adapter.list",
    "system.service_status",
    "system.resource_snapshot",
    "process.list",
    "process.find",
    "service.list",
    "service.status",
    "printer.list",
    "printer.status",
    "printer.queue.summary",
    "software.list",
    "software.find",
    "filesystem.free_space",
    "filesystem.path_exists",
    "filesystem.file_metadata",
    "eventlog.query",
    "eventlog.recent_errors",
]
ModuleCapabilityPlatformV1 = Literal["linux_amd64", "windows_amd64"]
ModuleCapabilityCategoryV1 = Literal["network", "system", "process", "service", "printer", "software", "eventlog", "filesystem"]
ModuleCapabilityRiskV1 = Literal["safe_read", "controlled_read"]
ModuleCapabilityFeatureFlagV1 = Literal[
    "endpoint_network_primitives_enabled",
    "endpoint_read_only_primitives_enabled",
    "endpoint_system_primitives_enabled",
    "endpoint_process_primitives_enabled",
    "endpoint_printer_primitives_enabled",
    "endpoint_software_primitives_enabled",
    "endpoint_filesystem_primitives_enabled",
    "endpoint_eventlog_primitives_enabled",
]
ModuleCapabilityPolicyV1 = Literal["network_target_policy", "none", "process_metadata", "service_catalog", "local_printers", "machine_software", "local_volumes", "logical_paths", "event_profile"]
ModuleCapabilityParameterTypeV1 = Literal["string", "integer", "enum"]
ModuleCapabilityParameterSourceV1 = Literal["input", "literal"]


class EndpointCapabilityParameterDescriptorV1(ContractModelV1):
    """Public, bounded authoring rule for one fixed primitive parameter."""

    name: str = Field(
        strict=True,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]{0,63}$",
    )
    value_type: ModuleCapabilityParameterTypeV1
    required: StrictBool
    allowed_sources: list[ModuleCapabilityParameterSourceV1] = Field(
        min_length=1,
        max_length=2,
    )
    enum_values: list[StrictStr] | None = Field(max_length=8)
    minimum: StrictInt | None
    maximum: StrictInt | None
    default_literal: StrictStr | StrictInt | None
    secret: Literal[False]

    @model_validator(mode="after")
    def validate_descriptor_shape(self) -> "EndpointCapabilityParameterDescriptorV1":
        if len(set(self.allowed_sources)) != len(self.allowed_sources):
            raise ValueError("parameter allowed_sources must not contain duplicates")
        if self.value_type == "enum":
            if not self.enum_values or len(set(self.enum_values)) != len(self.enum_values):
                raise ValueError("enum parameter must declare unique enum_values")
            if self.minimum is not None or self.maximum is not None:
                raise ValueError("enum parameter must not declare numeric bounds")
        elif self.enum_values is not None:
            raise ValueError("only enum parameters may declare enum_values")
        if self.value_type != "integer" and (
            self.minimum is not None or self.maximum is not None
        ):
            raise ValueError("only integer parameters may declare numeric bounds")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("parameter minimum must not exceed maximum")
        if self.default_literal is not None:
            expected = int if self.value_type == "integer" else str
            if type(self.default_literal) is not expected:
                raise ValueError("parameter default_literal type is invalid")
            if self.value_type == "enum" and self.default_literal not in self.enum_values:
                raise ValueError("enum default_literal must be declared")
        return self


class ModuleCapabilityAuthoringV1(ContractModelV1):
    """Stable public metadata for one fixed recipe-capable primitive."""

    capability: ModuleCapabilityNameV1
    display_name_ru: str = Field(strict=True, min_length=1, max_length=128)
    category: ModuleCapabilityCategoryV1
    parameter_schema_version: str = Field(strict=True, min_length=1, max_length=128)
    result_schema_version: str = Field(strict=True, min_length=1, max_length=128)
    platforms: list[ModuleCapabilityPlatformV1] = Field(min_length=1, max_length=2)
    minimum_agent_version: str = Field(
        strict=True,
        min_length=5,
        max_length=32,
        pattern=r"^\d+\.\d+\.\d+$",
    )
    risk: ModuleCapabilityRiskV1
    consent_required: Literal[False]
    feature_flag: ModuleCapabilityFeatureFlagV1
    policy: ModuleCapabilityPolicyV1
    parameters: list[EndpointCapabilityParameterDescriptorV1] = Field(max_length=4)
    execution_timeout_seconds: StrictInt = Field(ge=1, le=30)
    max_result_items: StrictInt = Field(ge=1, le=100)

    @model_validator(mode="after")
    def validate_parameter_names(self) -> "ModuleCapabilityAuthoringV1":
        names = [parameter.name for parameter in self.parameters]
        if len(set(names)) != len(names):
            raise ValueError("capability parameter names must be unique")
        return self


class ModuleCapabilityCatalogV1(ContractModelV1):
    """Versioned, closed discovery response without an execution surface."""

    schema_version: Literal["endpoint_module_capability_catalog_v1"]
    items: list[ModuleCapabilityAuthoringV1] = Field(min_length=6, max_length=32)


@dataclass(frozen=True, slots=True)
class ModuleCapabilityDescriptor:
    """Private binding from public metadata to fixed typed DTOs."""

    metadata: ModuleCapabilityAuthoringV1
    parameter_model: type[ContractModelV1]
    result_model: type[ContractModelV1]


def _descriptor(
    *,
    capability: ModuleCapabilityNameV1,
    display_name_ru: str,
    category: ModuleCapabilityCategoryV1,
    parameter_schema_version: str,
    result_schema_version: str,
    minimum_agent_version: str,
    feature_flag: ModuleCapabilityFeatureFlagV1,
    policy: ModuleCapabilityPolicyV1,
    parameter_model: type[ContractModelV1],
    result_model: type[ContractModelV1],
    parameters: tuple[EndpointCapabilityParameterDescriptorV1, ...],
    risk: ModuleCapabilityRiskV1 = "safe_read",
    execution_timeout_seconds: int = 10,
    max_result_items: int = 1,
    platforms: tuple[ModuleCapabilityPlatformV1, ...] = ("linux_amd64", "windows_amd64"),
) -> ModuleCapabilityDescriptor:
    return ModuleCapabilityDescriptor(
        metadata=ModuleCapabilityAuthoringV1(
            capability=capability,
            display_name_ru=display_name_ru,
            category=category,
            parameter_schema_version=parameter_schema_version,
            result_schema_version=result_schema_version,
            platforms=list(platforms),
            minimum_agent_version=minimum_agent_version,
            risk=risk,
            consent_required=False,
            feature_flag=feature_flag,
            policy=policy,
            parameters=list(parameters),
            execution_timeout_seconds=execution_timeout_seconds,
            max_result_items=max_result_items,
        ),
        parameter_model=parameter_model,
        result_model=result_model,
    )


def _parameter(
    name: str,
    value_type: ModuleCapabilityParameterTypeV1,
    allowed_sources: tuple[ModuleCapabilityParameterSourceV1, ...],
    *,
    enum_values: tuple[str, ...] | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> EndpointCapabilityParameterDescriptorV1:
    return EndpointCapabilityParameterDescriptorV1(
        name=name,
        value_type=value_type,
        required=True,
        allowed_sources=list(allowed_sources),
        enum_values=list(enum_values) if enum_values is not None else None,
        minimum=minimum,
        maximum=maximum,
        default_literal=None,
        secret=False,
    )


MODULE_CAPABILITY_REGISTRY: Mapping[ModuleCapabilityNameV1, ModuleCapabilityDescriptor] = {
    "dns.resolve": _descriptor(
        capability="dns.resolve",
        display_name_ru="Разрешение DNS-имени",
        category="network",
        parameter_schema_version="dns_resolve_parameters_v1",
        result_schema_version="dns_resolve_result_v1",
        minimum_agent_version="3.2.27",
        feature_flag="endpoint_network_primitives_enabled",
        policy="network_target_policy",
        parameter_model=DnsResolveParametersV1,
        result_model=DnsResolveResultV1,
        parameters=(
            _parameter("target", "string", ("input", "literal")),
            _parameter(
                "family",
                "enum",
                ("input", "literal"),
                enum_values=("any", "ipv4", "ipv6"),
            ),
        ),
    ),
    "network.ping": _descriptor(
        capability="network.ping",
        display_name_ru="Проверка доступности сети",
        category="network",
        parameter_schema_version="network_ping_parameters_v1",
        result_schema_version="network_ping_result_v1",
        minimum_agent_version="3.2.27",
        feature_flag="endpoint_network_primitives_enabled",
        policy="network_target_policy",
        parameter_model=NetworkPingParametersV1,
        result_model=NetworkPingResultV1,
        parameters=(
            _parameter("target", "string", ("input", "literal")),
            _parameter("count", "integer", ("input", "literal"), minimum=1, maximum=5),
            _parameter(
                "timeout_ms",
                "integer",
                ("input", "literal"),
                minimum=100,
                maximum=5000,
            ),
        ),
    ),
    "tcp.connect": _descriptor(
        capability="tcp.connect",
        display_name_ru="Проверка TCP-соединения",
        category="network",
        parameter_schema_version="tcp_connect_parameters_v1",
        result_schema_version="tcp_connect_result_v1",
        minimum_agent_version="3.2.27",
        feature_flag="endpoint_network_primitives_enabled",
        policy="network_target_policy",
        parameter_model=TcpConnectParametersV1,
        result_model=TcpConnectResultV1,
        parameters=(
            _parameter("target", "string", ("input", "literal")),
            _parameter("port", "integer", ("input", "literal"), minimum=1, maximum=65535),
            _parameter(
                "timeout_ms",
                "integer",
                ("input", "literal"),
                minimum=100,
                maximum=10000,
            ),
        ),
    ),
    "route.get": _descriptor(
        capability="route.get",
        display_name_ru="Просмотр маршрута",
        category="network",
        parameter_schema_version="route_get_parameters_v1",
        result_schema_version="route_get_result_v1",
        minimum_agent_version="3.2.29",
        feature_flag="endpoint_read_only_primitives_enabled",
        policy="network_target_policy",
        parameter_model=RouteGetParametersV1,
        result_model=RouteGetResultV1,
        parameters=(
            _parameter("target", "string", ("input", "literal")),
            _parameter("port", "integer", ("input", "literal"), minimum=1, maximum=65535),
            _parameter(
                "family",
                "enum",
                ("input", "literal"),
                enum_values=("any", "ipv4", "ipv6"),
            ),
            _parameter(
                "timeout_ms",
                "integer",
                ("input", "literal"),
                minimum=100,
                maximum=5000,
            ),
        ),
    ),
    "adapter.list": _descriptor(
        capability="adapter.list",
        display_name_ru="Список сетевых адаптеров",
        category="network",
        parameter_schema_version="adapter_list_parameters_v1",
        result_schema_version="adapter_list_result_v1",
        minimum_agent_version="3.2.29",
        feature_flag="endpoint_read_only_primitives_enabled",
        policy="none",
        parameter_model=AdapterListParametersV1,
        result_model=AdapterListResultV1,
        parameters=(),
        max_result_items=32,
    ),
    "system.service_status": _descriptor(
        capability="system.service_status",
        display_name_ru="Состояние службы",
        category="service",
        parameter_schema_version="service_status_parameters_v1",
        result_schema_version="service_status_result_v1",
        minimum_agent_version="3.2.29",
        feature_flag="endpoint_read_only_primitives_enabled",
        policy="none",
        parameter_model=ServiceStatusParametersV1,
        result_model=ServiceStatusResultV1,
        parameters=(
            _parameter(
                "service_key",
                "enum",
                ("literal",),
                enum_values=("endpoint_agent", "endpoint_agent_updater"),
            ),
        ),
    ),
    "system.resource_snapshot": _descriptor(
        capability="system.resource_snapshot",
        display_name_ru="Состояние ресурсов системы",
        category="system",
        parameter_schema_version="system_resource_snapshot_parameters_v1",
        result_schema_version="system_resource_snapshot_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_system_primitives_enabled",
        policy="none",
        parameter_model=SystemResourceSnapshotParametersV1,
        result_model=SystemResourceSnapshotResultV1,
        parameters=(),
    ),
    "process.list": _descriptor(
        capability="process.list",
        display_name_ru="Процессы",
        category="process",
        parameter_schema_version="process_list_parameters_v1",
        result_schema_version="process_list_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_process_primitives_enabled",
        policy="process_metadata",
        parameter_model=ProcessListParametersV1,
        result_model=ProcessListResultV1,
        parameters=(),
        risk="controlled_read",
        max_result_items=32,
    ),
    "process.find": _descriptor(
        capability="process.find",
        display_name_ru="Поиск процесса",
        category="process",
        parameter_schema_version="process_find_parameters_v1",
        result_schema_version="process_find_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_process_primitives_enabled",
        policy="process_metadata",
        parameter_model=ProcessFindParametersV1,
        result_model=ProcessFindResultV1,
        parameters=(_parameter("name", "string", ("input", "literal")),),
        max_result_items=20,
    ),
    "service.list": _descriptor(
        capability="service.list",
        display_name_ru="Список служб",
        category="service",
        parameter_schema_version="service_list_parameters_v1",
        result_schema_version="service_list_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_system_primitives_enabled",
        policy="service_catalog",
        parameter_model=ServiceListParametersV1,
        result_model=ServiceListResultV1,
        parameters=(),
        risk="controlled_read",
        max_result_items=3,
    ),
    "service.status": _descriptor(
        capability="service.status",
        display_name_ru="Проверка службы",
        category="service",
        parameter_schema_version="service_status_v2_parameters_v1",
        result_schema_version="service_status_v2_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_system_primitives_enabled",
        policy="service_catalog",
        parameter_model=ServiceStatusV2ParametersV1,
        result_model=ServiceStatusV2ResultV1,
        parameters=(_parameter("service_key", "enum", ("literal",), enum_values=("endpoint_agent", "endpoint_agent_updater", "print_service")),),
    ),
    "printer.list": _descriptor(
        capability="printer.list",
        display_name_ru="Принтеры",
        category="printer",
        parameter_schema_version="printer_list_parameters_v1",
        result_schema_version="printer_list_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_printer_primitives_enabled",
        policy="local_printers",
        parameter_model=PrinterListParametersV1,
        result_model=PrinterListResultV1,
        parameters=(),
        risk="controlled_read",
        max_result_items=16,
    ),
    "printer.status": _descriptor(
        capability="printer.status",
        display_name_ru="Состояние принтера",
        category="printer",
        parameter_schema_version="printer_status_parameters_v1",
        result_schema_version="printer_status_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_printer_primitives_enabled",
        policy="local_printers",
        parameter_model=PrinterStatusParametersV1,
        result_model=PrinterStatusResultV1,
        parameters=(_parameter("printer_name", "string", ("input", "literal")),),
    ),
    "printer.queue.summary": _descriptor(
        capability="printer.queue.summary",
        display_name_ru="Состояние очереди печати",
        category="printer",
        parameter_schema_version="printer_queue_summary_parameters_v1",
        result_schema_version="printer_queue_summary_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_printer_primitives_enabled",
        policy="local_printers",
        parameter_model=PrinterQueueSummaryParametersV1,
        result_model=PrinterQueueSummaryResultV1,
        parameters=(),
        risk="controlled_read",
        platforms=("windows_amd64",),
    ),
    "software.list": _descriptor(
        capability="software.list",
        display_name_ru="Установленное ПО",
        category="software",
        parameter_schema_version="software_list_parameters_v1",
        result_schema_version="software_list_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_software_primitives_enabled",
        policy="machine_software",
        parameter_model=SoftwareListParametersV1,
        result_model=SoftwareListResultV1,
        parameters=(),
        risk="controlled_read",
        max_result_items=32,
    ),
    "software.find": _descriptor(
        capability="software.find",
        display_name_ru="Проверка установленного ПО",
        category="software",
        parameter_schema_version="software_find_parameters_v1",
        result_schema_version="software_find_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_software_primitives_enabled",
        policy="machine_software",
        parameter_model=SoftwareFindParametersV1,
        result_model=SoftwareFindResultV1,
        parameters=(_parameter("name", "string", ("input", "literal")),),
        max_result_items=20,
    ),
    "filesystem.free_space": _descriptor(
        capability="filesystem.free_space",
        display_name_ru="Свободное место",
        category="filesystem",
        parameter_schema_version="filesystem_free_space_parameters_v1",
        result_schema_version="filesystem_free_space_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_filesystem_primitives_enabled",
        policy="local_volumes",
        parameter_model=FreeSpaceParametersV1,
        result_model=FreeSpaceResultV1,
        parameters=(),
        max_result_items=16,
    ),
    "filesystem.path_exists": _descriptor(
        capability="filesystem.path_exists",
        display_name_ru="Проверка файла или папки",
        category="filesystem",
        parameter_schema_version="filesystem_path_exists_parameters_v1",
        result_schema_version="filesystem_path_exists_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_filesystem_primitives_enabled",
        policy="logical_paths",
        parameter_model=PathExistsParametersV1,
        result_model=PathExistsResultV1,
        parameters=(_parameter("path_key", "enum", ("literal",), enum_values=("endpoint_install_root", "endpoint_data_root", "endpoint_runtime_manifest")),),
        risk="controlled_read",
    ),
    "filesystem.file_metadata": _descriptor(
        capability="filesystem.file_metadata",
        display_name_ru="Сведения о файле Agent",
        category="filesystem",
        parameter_schema_version="filesystem_file_metadata_parameters_v1",
        result_schema_version="filesystem_file_metadata_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_filesystem_primitives_enabled",
        policy="logical_paths",
        parameter_model=FileMetadataParametersV1,
        result_model=FileMetadataResultV1,
        parameters=(_parameter("path_key", "enum", ("literal",), enum_values=("endpoint_runtime_manifest",)),),
        risk="controlled_read",
    ),
    "eventlog.query": _descriptor(
        capability="eventlog.query",
        display_name_ru="Запрос журнала событий",
        category="eventlog",
        parameter_schema_version="eventlog_query_parameters_v1",
        result_schema_version="eventlog_query_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_eventlog_primitives_enabled",
        policy="event_profile",
        parameter_model=EventQueryParametersV1,
        result_model=EventQueryResultV1,
        parameters=(
            _parameter("profile", "enum", ("literal",), enum_values=("system", "application", "print", "endpoint")),
            _parameter("lookback_minutes", "integer", ("input", "literal"), minimum=1, maximum=60),
            _parameter("severity", "enum", ("literal",), enum_values=("error", "warning", "information")),
            _parameter("max_events", "integer", ("input", "literal"), minimum=1, maximum=32),
        ),
        risk="controlled_read",
        platforms=("windows_amd64",),
        execution_timeout_seconds=20,
        max_result_items=32,
    ),
    "eventlog.recent_errors": _descriptor(
        capability="eventlog.recent_errors",
        display_name_ru="Последние ошибки журнала",
        category="eventlog",
        parameter_schema_version="eventlog_recent_errors_parameters_v1",
        result_schema_version="eventlog_recent_errors_result_v1",
        minimum_agent_version="3.2.67",
        feature_flag="endpoint_eventlog_primitives_enabled",
        policy="event_profile",
        parameter_model=RecentErrorsParametersV1,
        result_model=RecentErrorsResultV1,
        parameters=(
            _parameter("profile", "enum", ("literal",), enum_values=("system", "application", "print", "endpoint")),
            _parameter("lookback_minutes", "integer", ("input", "literal"), minimum=1, maximum=60),
        ),
        risk="controlled_read",
        platforms=("windows_amd64",),
        execution_timeout_seconds=20,
        max_result_items=20,
    ),
}


def module_capability_catalog() -> ModuleCapabilityCatalogV1:
    """Return fixed public descriptors in stable authoring order."""
    return ModuleCapabilityCatalogV1(
        schema_version="endpoint_module_capability_catalog_v1",
        items=[entry.metadata for entry in MODULE_CAPABILITY_REGISTRY.values()],
    )


def module_capability_descriptor(capability: str) -> ModuleCapabilityDescriptor:
    """Resolve one closed capability without any dynamic import or dispatch."""
    try:
        return MODULE_CAPABILITY_REGISTRY[capability]  # type: ignore[index]
    except KeyError as error:
        raise ValueError("module capability is not catalog-defined") from error


def validate_module_capability_parameters(
    capability: str,
    parameters: Mapping[str, object],
) -> dict[str, object]:
    """Validate one typed payload and strip only the fixed schema discriminator."""
    descriptor = module_capability_descriptor(capability)
    model = descriptor.parameter_model.model_validate(
        {"schema_version": descriptor.metadata.parameter_schema_version, **parameters}
    )
    return model.model_dump(mode="json", exclude={"schema_version"})


def module_capability_gateway_parameter_schema(capability: str) -> dict[str, object]:
    """Build the static WSS parameter schema from one closed DTO binding."""
    descriptor = module_capability_descriptor(capability)
    parameter_schema = descriptor.parameter_model.model_json_schema()
    properties = deepcopy(parameter_schema.get("properties", {}))
    properties.pop("schema_version", None)
    for name, property_schema in properties.items():
        if name == "target" and isinstance(property_schema, dict):
            property_schema["pattern"] = r"^(?![\s\S]*://)[\s\S]*$"
    required = [
        name
        for name in parameter_schema.get("required", [])
        if name != "schema_version"
    ]
    schema: dict[str, object] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


__all__ = [
    "MODULE_CAPABILITY_REGISTRY",
    "EndpointCapabilityParameterDescriptorV1",
    "ModuleCapabilityAuthoringV1",
    "ModuleCapabilityCatalogV1",
    "ModuleCapabilityDescriptor",
    "ModuleCapabilityFeatureFlagV1",
    "ModuleCapabilityNameV1",
    "ModuleCapabilityParameterSourceV1",
    "ModuleCapabilityParameterTypeV1",
    "ModuleCapabilityPlatformV1",
    "ModuleCapabilityPolicyV1",
    "module_capability_catalog",
    "module_capability_descriptor",
    "module_capability_gateway_parameter_schema",
    "validate_module_capability_parameters",
]
