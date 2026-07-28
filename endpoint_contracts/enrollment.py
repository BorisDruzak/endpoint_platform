from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from .base import ContractModelV1


class EnrollmentRequestV1(ContractModelV1):
    schema_version: Literal["enrollment_request_v1"]
    platform: Literal["linux", "windows"]
    hardware_fingerprint: Annotated[str, Field(min_length=8, max_length=256)]
    installation_id: Annotated[str, Field(min_length=1, max_length=256)]
    requested_at: AwareDatetime


class EnrollmentResponseV1(ContractModelV1):
    device_id: UUID
    policy_id: Annotated[str, Field(min_length=1, max_length=256)]
    enrollment_receipt: Annotated[str, Field(min_length=1, max_length=256)]
    issued_at: AwareDatetime
