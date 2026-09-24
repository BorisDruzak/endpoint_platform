"""Closed logical service and privacy-preserving printer contracts."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictBool, model_validator

from .base import ContractModelV1
from .system_process_primitives import ErrorCodeV1


ServiceKeyV1 = Literal["endpoint_agent", "endpoint_agent_updater", "print_service"]
ServiceStateV1 = Literal["running", "stopped", "paused", "failed", "not_found", "unknown"]
StartModeV1 = Literal["automatic", "manual", "disabled", "unknown"]
PrinterNameV1 = Annotated[str, Field(strict=True, min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]+$")]


class ServiceFactV1(ContractModelV1):
    service_key: ServiceKeyV1
    display_name: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    installed: StrictBool
    state: ServiceStateV1
    startup_type: StartModeV1


class ServiceListParametersV1(ContractModelV1):
    schema_version: Literal["service_list_parameters_v1"]


class ServiceListResultV1(ContractModelV1):
    schema_version: Literal["service_list_result_v1"]
    services: list[ServiceFactV1] = Field(default_factory=list, max_length=3)
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime


class ServiceStatusParametersV1(ContractModelV1):
    schema_version: Literal["service_status_v2_parameters_v1"]
    service_key: ServiceKeyV1


class ServiceStatusResultV1(ContractModelV1):
    schema_version: Literal["service_status_v2_result_v1"]
    service: ServiceFactV1 | None = None
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result(self) -> "ServiceStatusResultV1":
        if self.status == "succeeded" and self.service is None:
            raise ValueError("successful service status requires a service fact")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed service status requires an error code")
        return self


class PrinterFactV1(ContractModelV1):
    name: PrinterNameV1
    driver_name: Annotated[str, Field(strict=True, min_length=1, max_length=128)] | None = None
    port_type: Literal["local", "network", "usb", "virtual", "unknown"]
    default: StrictBool
    state: Literal["ready", "offline", "paused", "error", "unknown"]


class PrinterListParametersV1(ContractModelV1):
    schema_version: Literal["printer_list_parameters_v1"]


class PrinterListResultV1(ContractModelV1):
    schema_version: Literal["printer_list_result_v1"]
    printers: list[PrinterFactV1] = Field(default_factory=list, max_length=16)
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime


class PrinterStatusParametersV1(ContractModelV1):
    schema_version: Literal["printer_status_parameters_v1"]
    printer_name: PrinterNameV1


class PrinterStatusResultV1(ContractModelV1):
    schema_version: Literal["printer_status_result_v1"]
    exists: StrictBool
    state: Literal["ready", "offline", "paused", "error", "unknown"]
    offline: StrictBool
    error: StrictBool
    paused: StrictBool
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime


class PrinterQueueSummaryParametersV1(ContractModelV1):
    schema_version: Literal["printer_queue_summary_parameters_v1"]


class PrinterQueueSummaryResultV1(ContractModelV1):
    schema_version: Literal["printer_queue_summary_result_v1"]
    job_count: Annotated[int, Field(strict=True, ge=0, le=10000)]
    printing_count: Annotated[int, Field(strict=True, ge=0, le=10000)]
    queued_count: Annotated[int, Field(strict=True, ge=0, le=10000)]
    paused_count: Annotated[int, Field(strict=True, ge=0, le=10000)]
    error_count: Annotated[int, Field(strict=True, ge=0, le=10000)]
    oldest_job_age_seconds: Annotated[int, Field(strict=True, ge=0, le=31536000)] | None = None
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_counts(self) -> "PrinterQueueSummaryResultV1":
        if any(count > self.job_count for count in (
            self.printing_count, self.queued_count, self.paused_count, self.error_count,
        )):
            raise ValueError("queue category count exceeds total")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed queue summary requires an error code")
        return self
