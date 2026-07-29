from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import ContractModelV1

ContextProfileV1 = Literal["baseline_v1", "health_v1", "network_v1", "diagnostic_v1"]
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


class BaselineSystemV1(ContractModelV1):
    platform: Literal["linux", "windows"]
    distribution: BoundedTextV1
    architecture: Literal["x86_64", "aarch64"]


class BaselineHardwareV1(ContractModelV1):
    manufacturer: BoundedTextV1
    model: BoundedTextV1
    cpu_model: BoundedTextV1
    memory_bytes: Annotated[int, Field(ge=1)]


class BaselineStorageV1(ContractModelV1):
    stable_key: StableKeyV1
    model: BoundedTextV1
    size_bytes: Annotated[int, Field(ge=1)]


class BaselineInterfaceV1(ContractModelV1):
    stable_key: StableKeyV1
    name: Annotated[str, Field(min_length=1, max_length=64)]
    link_type: Literal["ethernet", "loopback", "wireless", "other"]


class BaselineSoftwareV1(ContractModelV1):
    name: BoundedTextV1
    version: Annotated[str, Field(min_length=1, max_length=128)]
    source: Literal["installer", "package", "system"]


class BaselineSectionsV1(ContractModelV1):
    system: BaselineSystemV1
    hardware: BaselineHardwareV1
    storage: list[BaselineStorageV1] = Field(min_length=1, max_length=64)
    interfaces: list[BaselineInterfaceV1] = Field(max_length=64)
    software: list[BaselineSoftwareV1] = Field(max_length=256)


class HealthResourcesV1(ContractModelV1):
    uptime_seconds: Annotated[int, Field(ge=0)]
    load_1m: Annotated[float, Field(ge=0, le=1000000)]
    free_bytes: Annotated[int, Field(ge=0)]


class HealthServiceV1(ContractModelV1):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    status: Literal["active", "inactive", "failed", "unknown"]


class HealthSectionsV1(ContractModelV1):
    resources: HealthResourcesV1
    services: list[HealthServiceV1] = Field(max_length=64)


class NetworkRouteV1(ContractModelV1):
    interface: Annotated[str, Field(min_length=1, max_length=64)]
    gateway: Annotated[str | None, Field(max_length=64)] = None


class NetworkInterfaceV1(ContractModelV1):
    name: Annotated[str, Field(min_length=1, max_length=64)]
    addresses: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(max_length=16)


class NetworkSectionsV1(ContractModelV1):
    default_route: NetworkRouteV1
    interfaces: list[NetworkInterfaceV1] = Field(max_length=64)


class DiagnosticProcessV1(ContractModelV1):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    state: Literal["running", "sleeping", "stopped", "unknown"]


class DiagnosticSectionsV1(ContractModelV1):
    reason: Annotated[str, Field(min_length=1, max_length=256)]
    log_excerpt: Annotated[str | None, Field(max_length=8192)] = None
    processes: list[DiagnosticProcessV1] = Field(max_length=64)


ContextSectionsV1 = (
    BaselineSectionsV1 | HealthSectionsV1 | NetworkSectionsV1 | DiagnosticSectionsV1
)

_PROFILE_SECTION_MODELS: dict[ContextProfileV1, type[ContractModelV1]] = {
    "baseline_v1": BaselineSectionsV1,
    "health_v1": HealthSectionsV1,
    "network_v1": NetworkSectionsV1,
    "diagnostic_v1": DiagnosticSectionsV1,
}


class DeviceContextEnvelopeV1(ContractModelV1):
    schema_version: Literal["device_context_v1"]
    profile: ContextProfileV1
    collected_at: AwareDatetime
    sections: ContextSectionsV1
    warnings: list[ContextWarningCodeV1] = Field(default_factory=list, max_length=16)

    @field_validator("sections", mode="before")
    @classmethod
    def validate_profile_sections(cls, value: object, info: object) -> object:
        profile = getattr(info, "data", {}).get("profile")
        section_model = _PROFILE_SECTION_MODELS.get(profile)
        if section_model is None:
            return value
        return section_model.model_validate(value)

    @model_validator(mode="after")
    def validate_profile_section_pair(self) -> "DeviceContextEnvelopeV1":
        expected_model = _PROFILE_SECTION_MODELS[self.profile]
        if not isinstance(self.sections, expected_model):
            raise ValueError("sections must match profile")
        return self


class DeviceContextBaselineV1(DeviceContextEnvelopeV1):
    profile: Literal["baseline_v1"]
    sections: BaselineSectionsV1


class DeviceContextHealthV1(DeviceContextEnvelopeV1):
    profile: Literal["health_v1"]
    sections: HealthSectionsV1


class DeviceContextNetworkV1(DeviceContextEnvelopeV1):
    profile: Literal["network_v1"]
    sections: NetworkSectionsV1


class DeviceContextDiagnosticV1(DeviceContextEnvelopeV1):
    profile: Literal["diagnostic_v1"]
    sections: DiagnosticSectionsV1


class DeviceContextDiffChangeV1(ContractModelV1):
    code: ContextDiffChangeCodeV1
    summary: Annotated[str, Field(min_length=1, max_length=256)]


class DeviceContextDiffV1(ContractModelV1):
    schema_version: Literal["device_context_diff_v1"]
    profile: Literal["baseline_v1"]
    from_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    to_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    changes: list[DeviceContextDiffChangeV1] = Field(max_length=128)


def validate_context_result_item(value: object) -> DeviceContextEnvelopeV1:
    """Validate a single AgentResultV1 item as exactly one context envelope."""
    return DeviceContextEnvelopeV1.model_validate(value)
