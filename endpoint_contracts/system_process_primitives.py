"""Strict, bounded System and Process module primitive contracts."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from .base import ContractModelV1


ProcessNameV1 = Annotated[str, Field(strict=True, min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]+$")]
ProcessStateV1 = Annotated[str, Field(strict=True, min_length=1, max_length=32, pattern=r"^[a-z_]+$")]
ErrorCodeV1 = Annotated[str, Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")]


class SystemResourceSnapshotParametersV1(ContractModelV1):
    schema_version: Literal["system_resource_snapshot_parameters_v1"]


class SystemResourceSnapshotResultV1(ContractModelV1):
    schema_version: Literal["system_resource_snapshot_result_v1"]
    uptime_seconds: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)] | None = None
    cpu_percent: Annotated[float, Field(strict=True, ge=0, le=100)] | None = None
    memory_total_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)] | None = None
    memory_available_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)] | None = None
    system_drive_free_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)] | None = None
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result(self) -> "SystemResourceSnapshotResultV1":
        if self.status == "succeeded" and None in (
            self.uptime_seconds, self.cpu_percent, self.memory_total_bytes,
            self.memory_available_bytes, self.system_drive_free_bytes,
        ):
            raise ValueError("successful resource snapshot requires all facts")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed resource snapshot requires an error code")
        return self


class ProcessSummaryV1(ContractModelV1):
    pid: Annotated[int, Field(strict=True, ge=0, le=2**31 - 1)]
    name: ProcessNameV1
    state: ProcessStateV1
    cpu_percent: Annotated[float, Field(strict=True, ge=0, le=10000)] | None = None
    memory_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)] | None = None


class ProcessListParametersV1(ContractModelV1):
    schema_version: Literal["process_list_parameters_v1"]


class ProcessListResultV1(ContractModelV1):
    schema_version: Literal["process_list_result_v1"]
    processes: list[ProcessSummaryV1] = Field(default_factory=list, max_length=32)
    process_count: Annotated[int, Field(strict=True, ge=0, le=32)]
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result(self) -> "ProcessListResultV1":
        if self.process_count != len(self.processes):
            raise ValueError("process count must match bounded result")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed process list requires an error code")
        return self


class ProcessFindParametersV1(ContractModelV1):
    schema_version: Literal["process_find_parameters_v1"]
    name: ProcessNameV1


class ProcessFindResultV1(ContractModelV1):
    schema_version: Literal["process_find_result_v1"]
    present: bool
    process_count: Annotated[int, Field(strict=True, ge=0, le=2**31 - 1)]
    matches: list[ProcessSummaryV1] = Field(default_factory=list, max_length=20)
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result(self) -> "ProcessFindResultV1":
        if self.present != (self.process_count > 0) or self.process_count < len(self.matches):
            raise ValueError("process match count is inconsistent")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed process find requires an error code")
        return self
