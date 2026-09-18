"""Versioned safe context structures bundled with the public SDK.

These deliberately mirror only the safe Device Context projections consumed by
the SDK.  Keeping them here makes a built client wheel independent of the
Endpoint Platform application's internal source tree.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    "AGENT_CHANGED",
    "HARDWARE_CHANGED",
    "NETWORK_CHANGED",
    "PLATFORM_CHANGED",
    "RAM_CHANGED",
    "SOFTWARE_CHANGED",
    "STORAGE_CHANGED",
]
BoundedTextV1 = Annotated[str, Field(min_length=1, max_length=256)]
OptionalBoundedTextV1 = Annotated[str | None, Field(max_length=256)]
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


class InventorySystemV1(_SafeContract):
    hostname: OptionalBoundedTextV1 = None
    platform: Literal["linux", "windows"] | None = None
    os_name: OptionalBoundedTextV1 = None
    os_version: OptionalBoundedTextV1 = None
    os_build: OptionalBoundedTextV1 = None
    architecture: Literal["x86_64", "aarch64"] | None = None


class InventoryHardwareV1(_SafeContract):
    manufacturer: OptionalBoundedTextV1 = None
    model: OptionalBoundedTextV1 = None
    serial_number: OptionalBoundedTextV1 = None
    product_uuid: OptionalBoundedTextV1 = None
    cpu_model: OptionalBoundedTextV1 = None
    bios_vendor: OptionalBoundedTextV1 = None
    bios_version: OptionalBoundedTextV1 = None
    baseboard_manufacturer: OptionalBoundedTextV1 = None
    baseboard_model: OptionalBoundedTextV1 = None
    baseboard_serial: OptionalBoundedTextV1 = None


class InventoryMemoryModuleV1(_SafeContract):
    slot: OptionalBoundedTextV1 = None
    manufacturer: OptionalBoundedTextV1 = None
    part_number: OptionalBoundedTextV1 = None
    serial: OptionalBoundedTextV1 = None
    capacity_bytes: Annotated[int | None, Field(ge=1)] = None
    speed_mt_s: Annotated[int | None, Field(ge=1, le=1_000_000)] = None
    memory_type: Literal["DDR", "DDR2", "DDR3", "DDR4", "DDR5", "UNKNOWN"] | None = None


class InventoryMemoryV1(_SafeContract):
    total_bytes: Annotated[int | None, Field(ge=1)] = None
    memory_type: Literal["DDR", "DDR2", "DDR3", "DDR4", "DDR5", "UNKNOWN"] | None = None
    module_count: Annotated[int, Field(ge=0, le=64)]
    modules: list[InventoryMemoryModuleV1] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_module_count(self) -> "InventoryMemoryV1":
        if self.module_count < len(self.modules):
            raise ValueError("module_count cannot be less than modules length")
        return self


class InventoryPhysicalStorageV1(_SafeContract):
    stable_key: StableKeyV1
    model: OptionalBoundedTextV1 = None
    serial: OptionalBoundedTextV1 = None
    size_bytes: Annotated[int | None, Field(ge=1)] = None
    media_type: Literal["HDD", "SSD", "UNKNOWN"]
    bus_type: Literal["SATA", "NVME", "USB", "SAS", "OTHER", "UNKNOWN"]


class InventoryStorageV1(_SafeContract):
    physical_devices: list[InventoryPhysicalStorageV1] = Field(max_length=64)


class InventoryInterfaceV1(_SafeContract):
    name: Annotated[str, Field(min_length=1, max_length=64)]
    stable_key: StableKeyV1
    mac: Annotated[str | None, Field(pattern=r"^[0-9a-f]{12}$")] = None
    ipv4: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(max_length=16)
    ipv6: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(max_length=16)
    link_type: Literal["ethernet", "loopback", "wireless", "other"]
    operational_state: Literal["up", "down", "unknown"]

    @model_validator(mode="after")
    def validate_mac_stable_key(self) -> "InventoryInterfaceV1":
        if self.mac is not None and self.stable_key != f"mac-{self.mac}":
            raise ValueError("MAC interface stable_key must be canonical")
        return self


class InventorySectionsV1(_SafeContract):
    system: InventorySystemV1
    hardware: InventoryHardwareV1
    memory: InventoryMemoryV1
    storage: InventoryStorageV1
    interfaces: list[InventoryInterfaceV1] = Field(max_length=64)


class SessionSectionsV1(_SafeContract):
    current_user_login: Annotated[str | None, Field(max_length=256)] = None
    interactive_session_present: bool


class DeviceContextDiffChangeV1(_SafeContract):
    code: ContextDiffChangeCodeV1
    summary: Annotated[str, Field(min_length=1, max_length=256)]


class DeviceContextDiffV1(_SafeContract):
    schema_version: Literal["device_context_diff_v1"]
    profile: Literal["baseline_v1", "inventory_v1"]
    from_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    to_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    changes: list[DeviceContextDiffChangeV1] = Field(max_length=128)
