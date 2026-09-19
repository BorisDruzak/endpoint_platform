from typing import Annotated, ClassVar, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from .base import ContractModelV1
from .identity import HardwareFingerprintV1
from .json_types import (
    BoundedJsonKeyV1,
    BoundedJsonValueV1,
    validate_bounded_json,
)


OpaqueTransportSecretV1 = Annotated[
    str,
    StringConstraints(
        min_length=43,
        max_length=43,
        pattern=r"^[A-Za-z0-9_-]{43}$",
    ),
]


class _SecretSafeContractModelV1(ContractModelV1):
    _repr_secret_fields: ClassVar[frozenset[str]] = frozenset()

    def __repr_args__(self) -> list[tuple[str, object]]:
        return [
            (name, value)
            for name, value in super().__repr_args__()
            if name not in self._repr_secret_fields
        ]

_MAX_WINDOWS_INVENTORY_TEXT = 256
_MAX_WINDOWS_MACS = 32
_MAC_PATTERN = r"^[0-9a-f]{12}$"


class WindowsEnrollmentPolicyV1(ContractModelV1):
    """Strict campaign policy that enables universal Windows setup."""

    policy_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")]
    enrollment_mode: Literal["auto", "manual"]
    allowed_installer_releases: list[
        Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")]
    ] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def reject_duplicate_releases(self) -> "WindowsEnrollmentPolicyV1":
        if len(set(self.allowed_installer_releases)) != len(self.allowed_installer_releases):
            raise ValueError("installer releases must be unique")
        return self


class PreEnrollmentRequestCreateV1(_SecretSafeContractModelV1):
    """Secret-safe public Windows setup evidence; campaign choice is server-only."""

    _repr_secret_fields = frozenset({"hardware_fingerprint", "request_capability"})

    schema_version: Literal["pre_enrollment_request_create_v1"]
    platform: Literal["windows"]
    installation_id: Annotated[str, Field(min_length=1, max_length=128)]
    hardware_fingerprint: HardwareFingerprintV1
    request_capability: OpaqueTransportSecretV1
    installer_version: Annotated[str, Field(min_length=1, max_length=128)]
    installer_release_id: Annotated[str, Field(min_length=1, max_length=128)]
    requested_at: AwareDatetime
    hostname: Annotated[str, Field(min_length=1, max_length=_MAX_WINDOWS_INVENTORY_TEXT)]
    manufacturer: Annotated[str | None, Field(default=None, max_length=_MAX_WINDOWS_INVENTORY_TEXT)]
    model: Annotated[str | None, Field(default=None, max_length=_MAX_WINDOWS_INVENTORY_TEXT)]
    serial: Annotated[str | None, Field(default=None, max_length=_MAX_WINDOWS_INVENTORY_TEXT)]
    product_uuid: Annotated[str | None, Field(default=None, max_length=64)]
    macs: list[Annotated[str, Field(pattern=_MAC_PATTERN)]] = Field(
        default_factory=list,
        max_length=_MAX_WINDOWS_MACS,
    )

    @model_validator(mode="after")
    def reject_duplicate_macs(self) -> "PreEnrollmentRequestCreateV1":
        if len(set(self.macs)) != len(self.macs):
            raise ValueError("MAC addresses must be unique")
        return self


class PreEnrollmentRequestStatusV1(ContractModelV1):
    """Bounded polling response deliberately excluding claims and credentials."""

    schema_version: Literal["pre_enrollment_request_status_v1"]
    request_id: UUID
    status: Literal[
        "auto_approved",
        "waiting_approval",
        "review_required",
        "denied",
        "claim_issued",
        "device_registered",
        "waiting_wss",
        "completed",
        "expired",
        "failed",
        "cancelled",
    ]
    reason: Annotated[str | None, Field(default=None, max_length=128)]
    expires_at: AwareDatetime


class EnrollmentRequestV1(ContractModelV1):
    schema_version: Literal["enrollment_request_v1"]
    platform: Literal["linux", "windows"]
    hardware_fingerprint: HardwareFingerprintV1
    installation_id: Annotated[str, Field(min_length=1, max_length=256)]
    requested_at: AwareDatetime


class EnrollmentResponseV1(ContractModelV1):
    schema_version: Literal["enrollment_response_v1"]
    device_id: UUID
    policy_id: Annotated[str, Field(min_length=1, max_length=256)]
    enrollment_receipt: Annotated[str, Field(min_length=1, max_length=256)]
    issued_at: AwareDatetime


class AgentEnrollmentRequestV1(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({"hardware_fingerprint", "delivery_nonce"})

    schema_version: Literal["agent_enrollment_request_v1"]
    platform: Literal["linux", "windows"]
    hardware_fingerprint: HardwareFingerprintV1
    installation_id: Annotated[str, Field(min_length=1, max_length=256)]
    delivery_nonce: OpaqueTransportSecretV1
    requested_at: AwareDatetime


class AgentEnrollmentDeliveryV1(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({"enrollment_receipt", "device_token"})

    model_config = ConfigDict(
        json_schema_extra={
            "$comment": (
                "Aggregate policy node count and serialized byte size are "
                "enforced by the Pydantic model only."
            )
        }
    )

    schema_version: Literal["agent_enrollment_delivery_v1"]
    device_id: UUID
    policy_id: Annotated[str, Field(min_length=1, max_length=256)]
    policy: dict[BoundedJsonKeyV1, BoundedJsonValueV1] = Field(max_length=32)
    enrollment_receipt: OpaqueTransportSecretV1
    device_token: OpaqueTransportSecretV1
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def validate_policy(self) -> "AgentEnrollmentDeliveryV1":
        validate_bounded_json(self.policy)
        return self


class EnrollmentDeliveryProofV1(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({"enrollment_receipt", "hardware_fingerprint"})

    schema_version: Literal["enrollment_delivery_proof_v1"]
    enrollment_receipt: OpaqueTransportSecretV1
    hardware_fingerprint: HardwareFingerprintV1


class DeviceCredentialRotationV1(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({"device_token"})

    schema_version: Literal["device_credential_rotation_v1"]
    device_token: OpaqueTransportSecretV1
    overlap_expires_at: AwareDatetime
