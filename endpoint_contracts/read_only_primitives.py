"""Closed DTOs for fixed Endpoint safe-read primitives."""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import ContractModelV1
from .network_primitives import NetworkTargetV1


_HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?\Z"
)
_ADAPTER_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"
_PACKAGE_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$"
_ERROR_CODE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"

AdapterNameV1 = Annotated[
    str, Field(strict=True, min_length=1, max_length=64, pattern=_ADAPTER_NAME_PATTERN)
]
PackageVersionV1 = Annotated[
    str,
    Field(strict=True, min_length=1, max_length=64, pattern=_PACKAGE_VERSION_PATTERN),
]
ReadOnlyErrorCodeV1 = Annotated[
    str, Field(strict=True, min_length=1, max_length=64, pattern=_ERROR_CODE_PATTERN)
]


def _validate_network_target(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("network target must be trimmed and control-character-free")
    if "://" in value or "/" in value or "@" in value:
        raise ValueError("network target must be a hostname or IP address")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if _HOSTNAME_PATTERN.fullmatch(value) is None:
            raise ValueError("network target must be a valid hostname or IP address")
    return value


class RouteGetParametersV1(ContractModelV1):
    schema_version: Literal["route_get_parameters_v1"]
    target: NetworkTargetV1

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_network_target(value)


class RouteGetResultV1(ContractModelV1):
    schema_version: Literal["route_get_result_v1"]
    target: NetworkTargetV1
    family: Literal["ipv4", "ipv6"] | None = None
    local_address: NetworkTargetV1 | None = None
    status: Literal["succeeded", "failed"]
    error_code: ReadOnlyErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_network_target(value)

    @model_validator(mode="after")
    def validate_route_shape(self) -> "RouteGetResultV1":
        if self.status == "succeeded":
            if self.family is None or self.local_address is None or self.error_code is not None:
                raise ValueError("successful route result must contain one local address")
        elif self.family is not None or self.local_address is not None or self.error_code is None:
            raise ValueError("failed route result must contain only a stable error code")
        if self.local_address is not None:
            try:
                parsed = ipaddress.ip_address(self.local_address)
            except ValueError as error:
                raise ValueError("local address must be an IP address") from error
            if self.family != ("ipv4" if parsed.version == 4 else "ipv6"):
                raise ValueError("route family must match local address")
        return self


class AdapterListParametersV1(ContractModelV1):
    schema_version: Literal["adapter_list_parameters_v1"]


class AdapterSummaryV1(ContractModelV1):
    index: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)]
    name: AdapterNameV1


class AdapterListResultV1(ContractModelV1):
    schema_version: Literal["adapter_list_result_v1"]
    adapters: list[AdapterSummaryV1] = Field(default_factory=list, max_length=32)
    adapter_count: Annotated[int, Field(strict=True, ge=0, le=32)]
    status: Literal["succeeded", "failed"]
    error_code: ReadOnlyErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_adapter_shape(self) -> "AdapterListResultV1":
        if self.adapter_count != len(self.adapters):
            raise ValueError("adapter_count must match adapters")
        if len({(item.index, item.name) for item in self.adapters}) != len(self.adapters):
            raise ValueError("adapter entries must be unique")
        if self.status == "succeeded" and self.error_code is not None:
            raise ValueError("successful adapter result must not contain error_code")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed adapter result must contain error_code")
        return self


ServiceKeyV1 = Literal["endpoint_agent", "endpoint_agent_updater"]


class SystemServiceStatusParametersV1(ContractModelV1):
    schema_version: Literal["system_service_status_parameters_v1"]
    service_key: ServiceKeyV1


class SystemServiceStatusResultV1(ContractModelV1):
    schema_version: Literal["system_service_status_result_v1"]
    service_key: ServiceKeyV1
    platform: Literal["linux_amd64", "windows_amd64"]
    state: Literal["active", "inactive", "failed", "missing", "unknown"]
    package_kind: Literal["alt_rpm", "windows_msi"]
    package_version: PackageVersionV1 | None = None
    status: Literal["succeeded", "failed"]
    error_code: ReadOnlyErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_service_shape(self) -> "SystemServiceStatusResultV1":
        expected_package_kind = {
            "linux_amd64": "alt_rpm",
            "windows_amd64": "windows_msi",
        }[self.platform]
        if self.package_kind != expected_package_kind:
            raise ValueError("package kind must match the platform")
        if self.status == "succeeded" and self.error_code is not None:
            raise ValueError("successful service result must not contain error_code")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed service result must contain error_code")
        return self


__all__ = [
    "AdapterListParametersV1",
    "AdapterListResultV1",
    "AdapterSummaryV1",
    "RouteGetParametersV1",
    "RouteGetResultV1",
    "SystemServiceStatusParametersV1",
    "SystemServiceStatusResultV1",
]
