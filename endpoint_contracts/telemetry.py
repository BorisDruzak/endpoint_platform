from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from .base import ContractModelV1

PlatformV1 = Literal["linux", "windows"]
ArchiveTypeV1 = Literal["zip", "tar.gz"]


class AgentHeartbeatV1(ContractModelV1):
    schema_version: Literal["agent_heartbeat_v1"]
    device_id: UUID
    platform: PlatformV1
    agent_version: Annotated[str, Field(min_length=1, max_length=128)]
    reported_at: AwareDatetime


class AgentBuildRecommendationV1(ContractModelV1):
    schema_version: Literal["agent_build_recommendation_v1"]
    version: Annotated[str, Field(min_length=1, max_length=128)]
    platform: PlatformV1
    artifact_path: Annotated[str, Field(min_length=1, max_length=512)]
    artifact_size_bytes: Annotated[int, Field(ge=1)]
    sha256: Annotated[str, Field(pattern=r"^[a-fA-F0-9]{64}$")]
    minimum_launcher_version: Annotated[str, Field(min_length=1, max_length=128)]
    channel: Literal["stable", "beta", "canary"]
    archive_type: ArchiveTypeV1
    issued_at: AwareDatetime

    @field_validator("artifact_path")
    @classmethod
    def validate_relative_artifact_path(cls, value: str) -> str:
        if (
            value.startswith(("/", "\\"))
            or "\\" in value
            or ":" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise ValueError("artifact_path must be a relative POSIX path")
        return value
