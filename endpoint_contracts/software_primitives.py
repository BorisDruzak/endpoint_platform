"""Bounded machine-wide software inventory and plain-text find contracts."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictBool, field_validator, model_validator

from .base import ContractModelV1
from .system_process_primitives import ErrorCodeV1


SoftwareTextV1 = Annotated[str, Field(strict=True, min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]+$")]


class SoftwareFactV1(ContractModelV1):
    name: SoftwareTextV1
    version: Annotated[str, Field(strict=True, min_length=1, max_length=64)] | None = None
    publisher: SoftwareTextV1 | None = None
    source: Literal["windows_registry", "alt_rpm"]
    architecture: Annotated[str, Field(strict=True, min_length=1, max_length=32)] | None = None


class SoftwareListParametersV1(ContractModelV1):
    schema_version: Literal["software_list_parameters_v1"]


class SoftwareListResultV1(ContractModelV1):
    schema_version: Literal["software_list_result_v1"]
    software: list[SoftwareFactV1] = Field(default_factory=list, max_length=32)
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_failure(self) -> "SoftwareListResultV1":
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed software list requires an error code")
        return self


class SoftwareFindParametersV1(ContractModelV1):
    schema_version: Literal["software_find_parameters_v1"]
    name: SoftwareTextV1

    @field_validator("name")
    @classmethod
    def reject_patterns(cls, value: str) -> str:
        if any(character in value for character in "*?[]"):
            raise ValueError("software name must be plain text")
        return value


class SoftwareFindResultV1(ContractModelV1):
    schema_version: Literal["software_find_result_v1"]
    present: StrictBool
    matches: list[SoftwareFactV1] = Field(default_factory=list, max_length=20)
    status: Literal["succeeded", "failed"]
    error_code: ErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_result(self) -> "SoftwareFindResultV1":
        if self.status == "succeeded" and self.present != bool(self.matches):
            raise ValueError("software presence must match visible matches")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed software find requires an error code")
        return self
