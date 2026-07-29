"""Versioned safe context structures bundled with the public SDK.

These deliberately mirror only the safe Device Context projections consumed by
the SDK.  Keeping them here makes a built client wheel independent of the
Endpoint Platform application's internal source tree.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class _SafeContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


ContextWarningCodeV1 = Literal[
    "command_failed",
    "command_timed_out",
    "data_truncated",
    "permission_denied",
    "probe_unavailable",
    "redaction_applied",
    "source_unavailable",
    "unsupported_platform",
]
ContextDiffChangeCodeV1 = Literal[
    "agent_changed",
    "hardware_changed",
    "network_changed",
    "platform_changed",
    "software_changed",
    "storage_changed",
]
BoundedTextV1 = Annotated[str, Field(min_length=1, max_length=256)]
StableKeyV1 = Annotated[str, Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")]


class BaselineSystemV1(_SafeContract):
    platform: Literal["linux", "windows"]
    distribution: BoundedTextV1
    architecture: Literal["x86_64", "aarch64"]


class BaselineHardwareV1(_SafeContract):
    manufacturer: BoundedTextV1
    model: BoundedTextV1
    cpu_model: BoundedTextV1
    memory_bytes: Annotated[int, Field(ge=1)]


class BaselineStorageV1(_SafeContract):
    stable_key: StableKeyV1
    model: BoundedTextV1
    size_bytes: Annotated[int, Field(ge=1)]


class BaselineInterfaceV1(_SafeContract):
    stable_key: StableKeyV1
    name: Annotated[str, Field(min_length=1, max_length=64)]
    link_type: Literal["ethernet", "loopback", "wireless", "other"]


class BaselineSoftwareV1(_SafeContract):
    name: BoundedTextV1
    version: Annotated[str, Field(min_length=1, max_length=128)]
    source: Literal["installer", "package", "system"]


class BaselineSectionsV1(_SafeContract):
    system: BaselineSystemV1
    hardware: BaselineHardwareV1
    storage: list[BaselineStorageV1] = Field(min_length=1, max_length=64)
    interfaces: list[BaselineInterfaceV1] = Field(max_length=64)
    software: list[BaselineSoftwareV1] = Field(max_length=256)


class HealthResourcesV1(_SafeContract):
    uptime_seconds: Annotated[int, Field(ge=0)]
    load_1m: Annotated[float, Field(ge=0, le=1000000)]
    free_bytes: Annotated[int, Field(ge=0)]


class HealthServiceV1(_SafeContract):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    status: Literal["active", "inactive", "failed", "unknown"]


class HealthSectionsV1(_SafeContract):
    resources: HealthResourcesV1
    services: list[HealthServiceV1] = Field(max_length=64)


class NetworkRouteV1(_SafeContract):
    interface: Annotated[str, Field(min_length=1, max_length=64)]
    gateway: Annotated[str | None, Field(max_length=64)] = None


class NetworkInterfaceV1(_SafeContract):
    name: Annotated[str, Field(min_length=1, max_length=64)]
    addresses: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(max_length=16)


class NetworkSectionsV1(_SafeContract):
    default_route: NetworkRouteV1
    interfaces: list[NetworkInterfaceV1] = Field(max_length=64)


class DeviceContextDiffChangeV1(_SafeContract):
    code: ContextDiffChangeCodeV1
    summary: Annotated[str, Field(min_length=1, max_length=256)]


class DeviceContextDiffV1(_SafeContract):
    schema_version: Literal["device_context_diff_v1"]
    profile: Literal["baseline_v1"]
    from_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    to_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    changes: list[DeviceContextDiffChangeV1] = Field(max_length=128)
