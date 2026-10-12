"""Read-only, device-scoped projection of published module versions."""
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .base import ContractModelV1
from .modules import EndpointRecipeModuleSpecV1, ModuleKeyV1


ModuleUnavailableReasonV1 = Literal[
    "device_offline", "agent_facts_missing", "platform_unsupported",
    "agent_version_unsupported", "capability_not_announced", "feature_disabled",
    "network_policy_missing", "invalid_recipe",
]


class PublishedDeviceModuleV1(ContractModelV1):
    module_key: ModuleKeyV1
    display_name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    state: Literal["published"] = "published"
    recipe: EndpointRecipeModuleSpecV1 | None
    availability: Literal["available", "unavailable", "unknown"]
    reason_code: ModuleUnavailableReasonV1 | None

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if (self.availability == "available") != (self.reason_code is None):
            raise ValueError("blocked modules require a reason")
        if self.recipe is None and self.reason_code != "invalid_recipe":
            raise ValueError("missing recipe requires invalid projection")
        if self.recipe is not None and self.recipe.module_key != self.module_key:
            raise ValueError("recipe belongs to another module")
        return self


class EndpointDeviceModulesPageV1(ContractModelV1):
    schema_version: Literal["endpoint_device_modules_v1"] = "endpoint_device_modules_v1"
    device_id: UUID
    observed_at: AwareDatetime
    items: list[PublishedDeviceModuleV1] = Field(max_length=100)
    next_cursor: str | None = Field(max_length=1024)
