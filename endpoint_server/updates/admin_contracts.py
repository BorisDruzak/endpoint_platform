"""Provider-local contracts for one paused singleton canary cancellation."""

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field

from endpoint_contracts.updates import ArtifactNameV1, Sha256V1, UpdateIdentifierV1


def _nonnull(value: UUID) -> UUID:
    if value.int == 0:
        raise ValueError("nil identity is invalid")
    return value


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


NonNilUUID = Annotated[UUID, AfterValidator(_nonnull),
    Field(json_schema_extra={"not": {"const": "00000000-0000-0000-0000-000000000000"}})]
UTCDateTime = Annotated[AwareDatetime, AfterValidator(_utc)]
CancellationReason = Literal["trial_retired_after_verified_restoration"]


class _CancellationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", revalidate_instances="always")


class UpdateRolloutCancellationContextV1(_CancellationModel):
    rollout_id: NonNilUUID
    rollout_identifier: UpdateIdentifierV1
    mode: Literal["canary"]
    status: Literal["paused"]
    paused_at: UTCDateTime
    build_id: NonNilUUID
    build_identifier: UpdateIdentifierV1
    artifact_name: ArtifactNameV1
    artifact_sha256: Sha256V1
    target_id: NonNilUUID
    target_identifier: UpdateIdentifierV1
    device_id: NonNilUUID
    operation_identity: Sha256V1
    target_status: Literal["assigned", "requested", "scheduled"]


class UpdateRolloutRecoveryAttestationV1(_CancellationModel):
    procedure: Literal["task13_verified_guest_restoration_v1"]
    run_id: NonNilUUID
    evidence_sha256: Sha256V1
    verified_at: UTCDateTime


class UpdateRolloutCancellationRequestV1(_CancellationModel):
    schema_version: Literal["update_rollout_cancellation_request_v1"]
    cancellation_id: NonNilUUID
    expected: UpdateRolloutCancellationContextV1
    reason: CancellationReason
    recovery: UpdateRolloutRecoveryAttestationV1


class UpdateRolloutCancellationResponseV1(_CancellationModel):
    schema_version: Literal["update_rollout_cancellation_response_v1"]
    cancellation_id: NonNilUUID
    rollout_id: NonNilUUID
    rollout_identifier: UpdateIdentifierV1
    build_id: NonNilUUID
    build_identifier: UpdateIdentifierV1
    target_id: NonNilUUID
    target_identifier: UpdateIdentifierV1
    device_id: NonNilUUID
    operation_identity: Sha256V1
    artifact_sha256: Sha256V1
    reason: CancellationReason
    status: Literal["cancelled"]
    target_status: Literal["cancelled"]
    cancelled_at: UTCDateTime
    terminal_at: UTCDateTime


class UpdateCancellationUnavailableV1(_CancellationModel):
    code: Literal["update_cancellation_attempt_not_applied", "update_cancellation_outcome_unknown"]
    detail: Literal["update_cancellation_attempt_not_applied", "update_cancellation_outcome_unknown"]
