"""Strict models for the safe Endpoint Platform service API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, TypeAlias
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from endpoint_contracts.context import (
    BaselineSectionsV1,
    ContextWarningCodeV1,
    DeviceContextDiffV1,
    HealthSectionsV1,
    NetworkSectionsV1,
)


SafeContextProfile: TypeAlias = Literal["baseline_v1", "health_v1", "network_v1"]
_SAFE_PROFILES = frozenset(("baseline_v1", "health_v1", "network_v1"))


class SafeModel(BaseModel):
    """Reject fields outside the service's explicitly safe projections."""

    model_config = ConfigDict(extra="forbid")


class Device(SafeModel):
    id: UUID
    device_identifier: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    retired_at: datetime | None


class ContextProfileAvailability(SafeModel):
    profile: SafeContextProfile
    status: str = Field(min_length=1, max_length=32)
    last_collected_at: datetime | None


class ContextSnapshot(SafeModel):
    id: UUID
    profile: SafeContextProfile
    collected_at: datetime
    semantic_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    warnings: list[ContextWarningCodeV1] = Field(default_factory=list, max_length=16)
    sections: BaselineSectionsV1 | HealthSectionsV1 | NetworkSectionsV1

    @field_validator("sections", mode="before")
    @classmethod
    def validate_profile_sections(cls, value: object, info: object) -> object:
        profile = getattr(info, "data", {}).get("profile")
        models = {
            "baseline_v1": BaselineSectionsV1,
            "health_v1": HealthSectionsV1,
            "network_v1": NetworkSectionsV1,
        }
        model = models.get(profile)
        return value if model is None else model.model_validate(value)

    @model_validator(mode="after")
    def validate_profile_section_pair(self) -> "ContextSnapshot":
        expected = {
            "baseline_v1": BaselineSectionsV1,
            "health_v1": HealthSectionsV1,
            "network_v1": NetworkSectionsV1,
        }[self.profile]
        if not isinstance(self.sections, expected):
            raise ValueError("context sections do not match profile")
        return self


class DeviceContext(SafeModel):
    device: Device
    profiles: list[ContextProfileAvailability]
    snapshots: list[ContextSnapshot]


class Collection(SafeModel):
    id: UUID
    device_id: UUID
    profile: SafeContextProfile
    status: str = Field(min_length=1, max_length=32)
    requested_at: datetime
    result_received_at: datetime | None
    completed_at: datetime | None
    failure_code: str | None = Field(default=None, max_length=128)


class CollectionDetails(SafeModel):
    collection: Collection
    snapshot: ContextSnapshot | None


class ContextComparison(SafeModel):
    """Typed wrapper around the fixed-code baseline comparison contract."""

    comparison: DeviceContextDiffV1


def is_safe_profile(value: object) -> bool:
    """Return whether a runtime value can cross the public SDK profile boundary."""

    return isinstance(value, str) and value in _SAFE_PROFILES
