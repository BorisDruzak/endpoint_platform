"""Closed DTOs for read-only Endpoint network probe capabilities."""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import ContractModelV1


_HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?\Z"
)
_CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
_ERROR_CODE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"

NetworkTargetV1 = Annotated[str, Field(strict=True, min_length=1, max_length=253)]
StableErrorCodeV1 = Annotated[
    str, Field(strict=True, min_length=1, max_length=64, pattern=_ERROR_CODE_PATTERN)
]


def _validate_target(value: str) -> str:
    if value != value.strip() or _CONTROL_PATTERN.search(value):
        raise ValueError("network target must be trimmed and control-character-free")
    if "://" in value or "/" in value or "@" in value:
        raise ValueError("network target must be a hostname or IP address")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if _HOSTNAME_PATTERN.fullmatch(value) is None:
            raise ValueError("network target must be a valid hostname or IP address")
    return value


class NetworkAddressV1(ContractModelV1):
    family: Literal["ipv4", "ipv6"]
    address: NetworkTargetV1

    @model_validator(mode="after")
    def validate_address_family(self) -> "NetworkAddressV1":
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as error:
            raise ValueError("network address must be an IP address") from error
        expected_family = "ipv4" if parsed.version == 4 else "ipv6"
        if self.family != expected_family:
            raise ValueError("network address family must match address")
        return self


class DnsResolveParametersV1(ContractModelV1):
    schema_version: Literal["dns_resolve_parameters_v1"]
    target: NetworkTargetV1
    family: Literal["any", "ipv4", "ipv6"]

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_target(value)


class DnsResolveResultV1(ContractModelV1):
    schema_version: Literal["dns_resolve_result_v1"]
    target: NetworkTargetV1
    canonical_name: Annotated[str | None, Field(strict=True, min_length=1, max_length=253)] = None
    addresses: list[NetworkAddressV1] = Field(default_factory=list, max_length=16)
    address_count: Annotated[int, Field(strict=True, ge=0, le=16)]
    status: Literal["succeeded", "failed"]
    error_code: StableErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @field_validator("target", "canonical_name")
    @classmethod
    def validate_hostname_fields(cls, value: str | None) -> str | None:
        return _validate_target(value) if value is not None else value

    @model_validator(mode="after")
    def validate_count_and_status(self) -> "DnsResolveResultV1":
        if self.address_count != len(self.addresses):
            raise ValueError("address_count must match addresses")
        if self.status == "succeeded" and self.error_code is not None:
            raise ValueError("successful DNS result must not contain error_code")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed DNS result must contain error_code")
        return self


class NetworkPingParametersV1(ContractModelV1):
    schema_version: Literal["network_ping_parameters_v1"]
    target: NetworkTargetV1
    count: Annotated[int, Field(strict=True, ge=1, le=5)]
    timeout_ms: Annotated[int, Field(strict=True, ge=100, le=5000)]

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_target(value)


class NetworkPingResultV1(ContractModelV1):
    schema_version: Literal["network_ping_result_v1"]
    target: NetworkTargetV1
    resolved_ip: NetworkTargetV1 | None = None
    transmitted: Annotated[int, Field(strict=True, ge=0, le=5)]
    received: Annotated[int, Field(strict=True, ge=0, le=5)]
    packet_loss_percent: Annotated[float, Field(strict=True, ge=0, le=100)]
    min_ms: Annotated[float, Field(strict=True, ge=0, le=60000)] | None = None
    avg_ms: Annotated[float, Field(strict=True, ge=0, le=60000)] | None = None
    max_ms: Annotated[float, Field(strict=True, ge=0, le=60000)] | None = None
    reachable: bool
    status: Literal["succeeded", "failed"]
    error_code: StableErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_target(value)

    @field_validator("resolved_ip")
    @classmethod
    def validate_resolved_ip(cls, value: str | None) -> str | None:
        if value is None:
            return value
        try:
            ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("resolved_ip must be an IP address") from error
        return value

    @model_validator(mode="after")
    def validate_measurements_and_status(self) -> "NetworkPingResultV1":
        if self.received > self.transmitted:
            raise ValueError("received must not exceed transmitted")
        if self.reachable != (self.received > 0):
            raise ValueError("reachable must match received")
        latencies = (self.min_ms, self.avg_ms, self.max_ms)
        if self.received == 0 and any(item is not None for item in latencies):
            raise ValueError("unreachable result must not contain latency values")
        if self.received > 0 and any(item is None for item in latencies):
            raise ValueError("reachable result must contain all latency values")
        if all(item is not None for item in latencies) and not (
            self.min_ms <= self.avg_ms <= self.max_ms
        ):
            raise ValueError("latencies must be ordered")
        if self.status == "succeeded" and self.error_code is not None:
            raise ValueError("successful ping result must not contain error_code")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed ping result must contain error_code")
        return self


class TcpConnectParametersV1(ContractModelV1):
    schema_version: Literal["tcp_connect_parameters_v1"]
    target: NetworkTargetV1
    port: Annotated[int, Field(strict=True, ge=1, le=65535)]
    timeout_ms: Annotated[int, Field(strict=True, ge=100, le=10000)]

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_target(value)


class TcpConnectResultV1(ContractModelV1):
    schema_version: Literal["tcp_connect_result_v1"]
    target: NetworkTargetV1
    resolved_ip: NetworkTargetV1 | None = None
    port: Annotated[int, Field(strict=True, ge=1, le=65535)]
    reachable: bool
    latency_ms: Annotated[float, Field(strict=True, ge=0, le=60000)] | None = None
    status: Literal["succeeded", "failed"]
    error_code: StableErrorCodeV1 | None = None
    collected_at: AwareDatetime

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_target(value)

    @field_validator("resolved_ip")
    @classmethod
    def validate_resolved_ip(cls, value: str | None) -> str | None:
        if value is None:
            return value
        try:
            ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("resolved_ip must be an IP address") from error
        return value

    @model_validator(mode="after")
    def validate_status(self) -> "TcpConnectResultV1":
        if self.reachable != (self.latency_ms is not None):
            raise ValueError("reachable must match latency availability")
        if self.status == "succeeded" and self.error_code is not None:
            raise ValueError("successful TCP result must not contain error_code")
        if self.status == "failed" and self.error_code is None:
            raise ValueError("failed TCP result must contain error_code")
        return self


__all__ = [
    "DnsResolveParametersV1",
    "DnsResolveResultV1",
    "NetworkAddressV1",
    "NetworkPingParametersV1",
    "NetworkPingResultV1",
    "TcpConnectParametersV1",
    "TcpConnectResultV1",
]
