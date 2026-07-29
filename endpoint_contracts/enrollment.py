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


class EnrollmentRequestV1(ContractModelV1):
    schema_version: Literal["enrollment_request_v1"]
    platform: Literal["linux", "windows"]
    hardware_fingerprint: Annotated[str, Field(min_length=8, max_length=256)]
    installation_id: Annotated[str, Field(min_length=1, max_length=256)]
    requested_at: AwareDatetime


class EnrollmentResponseV1(ContractModelV1):
    schema_version: Literal["enrollment_response_v1"]
    device_id: UUID
    policy_id: Annotated[str, Field(min_length=1, max_length=256)]
    enrollment_receipt: Annotated[str, Field(min_length=1, max_length=256)]
    issued_at: AwareDatetime


class _SecretSafeContractModelV1(ContractModelV1):
    _repr_secret_fields: ClassVar[frozenset[str]] = frozenset()

    def __repr_args__(self) -> list[tuple[str, object]]:
        return [
            (name, value)
            for name, value in super().__repr_args__()
            if name not in self._repr_secret_fields
        ]


class AgentEnrollmentRequestV1(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({"hardware_fingerprint", "delivery_nonce"})

    schema_version: Literal["agent_enrollment_request_v1"]
    platform: Literal["linux", "windows"]
    hardware_fingerprint: Annotated[
        str,
        Field(min_length=8, max_length=256),
    ]
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
    hardware_fingerprint: Annotated[
        str,
        Field(min_length=8, max_length=256),
    ]


class DeviceCredentialRotationV1(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({"device_token"})

    schema_version: Literal["device_credential_rotation_v1"]
    device_token: OpaqueTransportSecretV1
    overlap_expires_at: AwareDatetime
