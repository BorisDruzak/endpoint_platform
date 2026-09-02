"""Closed contracts for the approved Endpoint read-only primitive set."""

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
_INTERFACE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$"
_ERROR_CODE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"

InterfaceNameV1 = Annotated[
    str, Field(strict=True, min_length=1, max_length=128, pattern=_INTERFACE_NAME_PATTERN)
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


def _validate_ip(value: str, *, version: int | None = None) -> str:
    if "%" in value:
        raise ValueError("IP address must not include a scope identifier")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("value must be an IP address") from error
    if version is not None and address.version != version:
        raise ValueError("IP address family is invalid")
    return str(address)


class RouteGetParametersV1(ContractModelV1):
    schema_version: Literal["route_get_parameters_v1"]
    target: NetworkTargetV1
    port: Annotated[int, Field(strict=True, ge=1, le=65535)]
    family: Literal["any", "ipv4", "ipv6"]
    timeout_ms: Annotated[int, Field(strict=True, ge=100, le=5000)]

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_network_target(value)


class RouteGetResultV1(ContractModelV1):
    schema_version: Literal["route_get_result_v1"]
    target: NetworkTargetV1
    resolved_ip: str | None = None
    family: Literal["ipv4", "ipv6"] | None = None
    port: Annotated[int, Field(strict=True, ge=1, le=65535)]
    source_ip: str | None = None
    interface_name: InterfaceNameV1 | None = None
    strategy: Literal["udp_socket_inference"] = "udp_socket_inference"
    status: Literal["succeeded", "failed"]
    error_code: ReadOnlyErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_network_target(value)

    @field_validator("resolved_ip")
    @classmethod
    def validate_resolved_ip(cls, value: str | None) -> str | None:
        return None if value is None else _validate_ip(value)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        return None if value is None else _validate_ip(value)

    @model_validator(mode="after")
    def validate_route_shape(self) -> "RouteGetResultV1":
        if self.status == "succeeded":
            if (
                self.resolved_ip is None
                or self.family is None
                or self.source_ip is None
                or self.error_code is not None
            ):
                raise ValueError("successful route result must contain inferred route values")
            if ipaddress.ip_address(self.resolved_ip).version != (4 if self.family == "ipv4" else 6):
                raise ValueError("route family must match resolved IP")
        elif (
            self.error_code is None
            or self.resolved_ip is not None
            or self.family is not None
            or self.source_ip is not None
            or self.interface_name is not None
        ):
            raise ValueError("failed route result must contain only a stable error code")
        return self


class AdapterListParametersV1(ContractModelV1):
    schema_version: Literal["adapter_list_parameters_v1"]


class AdapterSummaryItemV1(ContractModelV1):
    name: InterfaceNameV1
    state: Literal["up", "down", "unknown"]
    kind: Literal["ethernet", "wifi", "loopback", "tunnel", "virtual", "unknown"]
    primary: bool
    ipv4_addresses: list[str] = Field(default_factory=list, max_length=4)
    ipv6_addresses: list[str] = Field(default_factory=list, max_length=4)
    mtu: Annotated[int, Field(strict=True, ge=0, le=65535)]
    speed_mbps: Annotated[int, Field(strict=True, ge=0, le=1_000_000)]

    @field_validator("ipv4_addresses")
    @classmethod
    def validate_ipv4_addresses(cls, values: list[str]) -> list[str]:
        return [_validate_ip(value, version=4) for value in values]

    @field_validator("ipv6_addresses")
    @classmethod
    def validate_ipv6_addresses(cls, values: list[str]) -> list[str]:
        return [_validate_ip(value, version=6) for value in values]


class AdapterListResultV1(ContractModelV1):
    schema_version: Literal["adapter_list_result_v1"]
    adapters: list[AdapterSummaryItemV1] = Field(default_factory=list, max_length=32)
    adapter_count: Annotated[int, Field(strict=True, ge=0, le=32)]
    up_count: Annotated[int, Field(strict=True, ge=0, le=32)]
    status: Literal["succeeded", "failed"]
    error_code: ReadOnlyErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_adapter_shape(self) -> "AdapterListResultV1":
        if self.adapter_count != len(self.adapters):
            raise ValueError("adapter_count must match adapters")
        if self.up_count != sum(item.state == "up" for item in self.adapters):
            raise ValueError("up_count must match adapters")
        if len({item.name for item in self.adapters}) != len(self.adapters):
            raise ValueError("adapter names must be unique")
        if self.status == "succeeded" and self.error_code is not None:
            raise ValueError("successful adapter result must not contain error_code")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed adapter result must contain error_code")
        return self


ServiceKeyV1 = Literal["endpoint_agent", "endpoint_agent_updater"]


class ServiceStatusParametersV1(ContractModelV1):
    schema_version: Literal["service_status_parameters_v1"]
    service_key: ServiceKeyV1


class ServiceStatusResultV1(ContractModelV1):
    schema_version: Literal["service_status_result_v1"]
    service_key: ServiceKeyV1
    installed: bool
    state: Literal["running", "stopped", "paused", "failed", "not_found", "unknown"]
    start_mode: Literal["automatic", "manual", "disabled", "unknown"]
    status: Literal["succeeded", "failed"]
    error_code: ReadOnlyErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @model_validator(mode="after")
    def validate_service_shape(self) -> "ServiceStatusResultV1":
        if self.status == "succeeded" and self.error_code is not None:
            raise ValueError("successful service result must not contain error_code")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed service result must contain error_code")
        return self


__all__ = [
    "AdapterListParametersV1",
    "AdapterListResultV1",
    "AdapterSummaryItemV1",
    "RouteGetParametersV1",
    "RouteGetResultV1",
    "ServiceStatusParametersV1",
    "ServiceStatusResultV1",
]
