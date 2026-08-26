"""Closed declarative recipe contract for Endpoint-owned module versions."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StrictInt, StrictStr, model_validator

from .base import ContractModelV1


ModuleInputNameV1 = Annotated[
    str,
    Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$"),
]
ModuleStepNameV1 = Annotated[
    str,
    Field(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$"),
]
ModuleKeyV1 = Annotated[
    str,
    Field(
        strict=True,
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){1,7}$",
    ),
]


class ModuleRecipeInputV1(ContractModelV1):
    name: ModuleInputNameV1
    value_type: Literal["string", "integer"]


class RecipeInputBindingV1(ContractModelV1):
    kind: Literal["input"]
    name: ModuleInputNameV1


class RecipeLiteralBindingV1(ContractModelV1):
    kind: Literal["literal"]
    value: StrictStr | StrictInt


RecipeParameterBindingV1 = Annotated[
    RecipeInputBindingV1 | RecipeLiteralBindingV1,
    Field(discriminator="kind"),
]


class EndpointRecipeStepV1(ContractModelV1):
    step_id: ModuleStepNameV1
    capability: Literal["dns.resolve", "network.ping", "tcp.connect"]
    parameters: dict[ModuleInputNameV1, RecipeParameterBindingV1] = Field(
        min_length=1,
        max_length=3,
    )


class EndpointRecipeModuleSpecV1(ContractModelV1):
    """A declarative, no-branching recipe expanded only by Endpoint Platform."""

    schema_version: Literal["endpoint_recipe_module_v1"]
    module_key: ModuleKeyV1
    supported_platforms: list[Literal["linux_amd64", "windows_amd64"]] = Field(
        min_length=1,
        max_length=2,
    )
    inputs: list[ModuleRecipeInputV1] = Field(default_factory=list, max_length=8)
    steps: list[EndpointRecipeStepV1] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_unique_declarative_names(self) -> "EndpointRecipeModuleSpecV1":
        if len(set(self.supported_platforms)) != len(self.supported_platforms):
            raise ValueError("supported_platforms must not contain duplicates")
        input_names = [item.name for item in self.inputs]
        if len(set(input_names)) != len(input_names):
            raise ValueError("recipe input names must be unique")
        step_ids = [item.step_id for item in self.steps]
        if len(set(step_ids)) != len(step_ids):
            raise ValueError("recipe step_id values must be unique")
        return self


class ModuleVersionCreateV1(ContractModelV1):
    schema_version: Literal["module_version_create_v1"]
    display_name: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    version: Annotated[str, Field(strict=True, min_length=5, max_length=64, pattern=r"^\d+\.\d+\.\d+$")]
    recipe: EndpointRecipeModuleSpecV1


__all__ = [
    "EndpointRecipeModuleSpecV1",
    "EndpointRecipeStepV1",
    "ModuleRecipeInputV1",
    "RecipeInputBindingV1",
    "RecipeLiteralBindingV1",
    "RecipeParameterBindingV1",
]
