from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AnyUrl, Field, StringConstraints, model_validator

from .base import ContractModelV1

UpdatePlatformV1 = Literal["linux_amd64", "windows_amd64"]
UpdateChannelV1 = Literal["stable", "canary"]
UpdateArchiveTypeV1 = Literal["zip", "tar.gz"]
UpdateRolloutModeV1 = Literal["canary", "bulk", "rollback"]
UpdateAcknowledgementStatusV1 = Literal["requested", "scheduled"]
UpdateReportStatusV1 = Literal["applied", "failed", "rolled_back"]

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z"
_SEMVER_PATTERN = (
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z"
)
_ARTIFACT_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}\z"
_SAFE_CODE_PATTERN = r"^[a-z][a-z0-9._-]{0,127}\z"
_SAFE_MESSAGE_PATTERN = r"^[^\r\n]{1,512}\z"
_SAFE_MESSAGE_PATH = re.compile(r"(?:^|[\s'\"(])(?:[A-Za-z]:[\\/]|/|\\\\)")

_IDENTIFIER_JSON_SCHEMA_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(?![\s\S])"
_SEMVER_JSON_SCHEMA_PATTERN = (
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?![\s\S])"
)
_ARTIFACT_NAME_JSON_SCHEMA_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}(?![\s\S])"
_SHA256_JSON_SCHEMA_PATTERN = r"^[0-9a-f]{64}(?![\s\S])"
_SAFE_CODE_JSON_SCHEMA_PATTERN = r"^[a-z][a-z0-9._-]{0,127}(?![\s\S])"
_SAFE_MESSAGE_JSON_SCHEMA_PATTERN = r"^[^\r\n]{1,512}(?![\s\S])"

UpdateIdentifierV1 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=_IDENTIFIER_PATTERN),
    Field(json_schema_extra={"pattern": _IDENTIFIER_JSON_SCHEMA_PATTERN}),
]
SemanticVersionV1 = Annotated[
    str,
    StringConstraints(min_length=5, max_length=128, pattern=_SEMVER_PATTERN),
    Field(json_schema_extra={"pattern": _SEMVER_JSON_SCHEMA_PATTERN}),
]
ArtifactNameV1 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=256, pattern=_ARTIFACT_NAME_PATTERN),
    Field(json_schema_extra={"pattern": _ARTIFACT_NAME_JSON_SCHEMA_PATTERN}),
]
Sha256V1 = Annotated[
    str,
    StringConstraints(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
    Field(json_schema_extra={"pattern": _SHA256_JSON_SCHEMA_PATTERN}),
]
SafeCodeV1 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=_SAFE_CODE_PATTERN),
    Field(json_schema_extra={"pattern": _SAFE_CODE_JSON_SCHEMA_PATTERN}),
]
SafeMessageV1 = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512, pattern=_SAFE_MESSAGE_PATTERN),
    Field(json_schema_extra={"pattern": _SAFE_MESSAGE_JSON_SCHEMA_PATTERN}),
]


class _ImmutableUpdateManifestV1(ContractModelV1):
    build_identifier: UpdateIdentifierV1
    version: SemanticVersionV1
    platform: UpdatePlatformV1
    channel: UpdateChannelV1
    artifact_url: AnyUrl
    artifact_name: ArtifactNameV1
    archive_type: UpdateArchiveTypeV1
    sha256: Sha256V1
    size: Annotated[int, Field(gt=0, le=2**63 - 1)]

    @model_validator(mode="after")
    def validate_immutable_artifact(self) -> _ImmutableUpdateManifestV1:
        parsed = urlsplit(str(self.artifact_url))
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("artifact_url must be an absolute HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("artifact_url must not contain credentials")
        if parsed.fragment:
            raise ValueError("artifact_url must not contain a fragment")
        if self.archive_type == "zip" and not self.artifact_name.endswith(".zip"):
            raise ValueError("artifact_name must match archive_type")
        if self.archive_type == "tar.gz" and not self.artifact_name.endswith(".tar.gz"):
            raise ValueError("artifact_name must match archive_type")
        return self


class UpdateBuildManifestV1(_ImmutableUpdateManifestV1):
    schema_version: Literal["update_build_manifest_v1"]
    release_notes: Annotated[str, Field(min_length=1, max_length=4096)] | None = None


class UpdateRolloutCreateV1(ContractModelV1):
    schema_version: Literal["update_rollout_v1"]
    build_identifier: UpdateIdentifierV1
    mode: UpdateRolloutModeV1
    device_ids: Annotated[list[UUID], Field(min_length=1, max_length=10_000)]
    reason: Annotated[str, Field(min_length=1, max_length=512)] | None = None

    @model_validator(mode="after")
    def validate_unique_device_ids(self) -> UpdateRolloutCreateV1:
        if len(set(self.device_ids)) != len(self.device_ids):
            raise ValueError("device_ids must be unique")
        return self


class AgentUpdateRecommendationV1(_ImmutableUpdateManifestV1):
    schema_version: Literal["agent_update_recommendation_v1"]
    operation_id: UUID
    reason: Annotated[str, Field(min_length=1, max_length=512)] | None = None


class AgentUpdateAcknowledgementV1(ContractModelV1):
    schema_version: Literal["agent_update_ack_v1"]
    status: UpdateAcknowledgementStatusV1


class AgentUpdateReportV1(ContractModelV1):
    schema_version: Literal["agent_update_report_v1"]
    report_key: UpdateIdentifierV1
    status: UpdateReportStatusV1
    reported_version: SemanticVersionV1
    safe_code: SafeCodeV1 | None = None
    safe_message: SafeMessageV1 | None = None

    @model_validator(mode="after")
    def validate_safe_message(self) -> AgentUpdateReportV1:
        if self.safe_message and _SAFE_MESSAGE_PATH.search(self.safe_message):
            raise ValueError("safe_message must not contain an absolute path")
        return self
