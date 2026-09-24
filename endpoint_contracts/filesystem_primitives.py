"""Logical-path filesystem facts; no arbitrary path or file contents."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictBool, model_validator

from .base import ContractModelV1
from .system_process_primitives import ErrorCodeV1


LogicalPathKeyV1 = Literal["endpoint_install_root", "endpoint_data_root", "endpoint_runtime_manifest"]


class FreeSpaceParametersV1(ContractModelV1):
    schema_version: Literal["filesystem_free_space_parameters_v1"]


class VolumeFactV1(ContractModelV1):
    volume_key: Annotated[str, Field(strict=True, min_length=1, max_length=32, pattern=r"^(?:system|local_[1-9][0-9]?)$")]
    filesystem_type: Annotated[str, Field(strict=True, min_length=1, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")]
    total_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    free_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]


class FreeSpaceResultV1(ContractModelV1):
    schema_version: Literal["filesystem_free_space_result_v1"]
    volumes: list[VolumeFactV1] = Field(default_factory=list, max_length=16)
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime


class PathExistsParametersV1(ContractModelV1):
    schema_version: Literal["filesystem_path_exists_parameters_v1"]
    path_key: LogicalPathKeyV1


class PathExistsResultV1(ContractModelV1):
    schema_version: Literal["filesystem_path_exists_result_v1"]
    path_key: LogicalPathKeyV1
    exists: StrictBool
    kind: Literal["file", "directory", "other", "missing"]
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime


class FileMetadataParametersV1(ContractModelV1):
    schema_version: Literal["filesystem_file_metadata_parameters_v1"]
    path_key: Literal["endpoint_runtime_manifest"]


class FileMetadataResultV1(ContractModelV1):
    schema_version: Literal["filesystem_file_metadata_result_v1"]
    path_key: Literal["endpoint_runtime_manifest"]
    exists: StrictBool
    size: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)] | None = None
    modified_at: AwareDatetime | None = None
    version: Annotated[str, Field(strict=True, min_length=1, max_length=32)] | None = None
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result(self) -> "FileMetadataResultV1":
        if self.status == "succeeded" and self.exists and (self.size is None or self.modified_at is None):
            raise ValueError("existing file requires safe metadata")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed file metadata requires an error code")
        return self
