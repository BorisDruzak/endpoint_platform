"""Linux source-bound enrollment, separate from immutable Windows wire shapes."""
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .base import ContractModelV1
from .enrollment import _SecretSafeContractModelV1
from .identity import HardwareFingerprintV1
from .linux_installation_lifecycle import LinuxNativeSource


class LinuxEnrollmentPolicyV1(ContractModelV1):
    policy_id: str = Field(min_length=1, max_length=128, pattern=r'^[a-z0-9][a-z0-9._-]*$')
    enrollment_mode: Literal['auto', 'manual']
    allowed_native_releases: list[UUID] = Field(min_length=1, max_length=64)

    @model_validator(mode='after')
    def unique_sources(self):
        if len(set(self.allowed_native_releases)) != len(self.allowed_native_releases):
            raise ValueError('Native sources must be unique')
        return self


# Common evidence constraints match canonical request evidence. Windows fields
# are deliberately absent rather than populated with fabricated installer IDs.
class LinuxPreEnrollmentRequestCreateV1(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({'hardware_fingerprint', 'request_capability'})
    schema_version: Literal['linux_pre_enrollment_request_create_v1']
    platform: Literal['linux']
    installation_id: Annotated[str, Field(min_length=1, max_length=128)]
    hardware_fingerprint: HardwareFingerprintV1
    request_capability: Annotated[str, Field(min_length=43, max_length=43, pattern=r'^[A-Za-z0-9_-]{43}$')]
    native: LinuxNativeSource
    requested_at: AwareDatetime
    hostname: str = Field(min_length=1, max_length=256)
    manufacturer: str | None = Field(default=None, max_length=256)
    model: str | None = Field(default=None, max_length=256)
    serial: str | None = Field(default=None, max_length=256)
    product_uuid: str | None = Field(default=None, max_length=64)
    macs: list[Annotated[str, Field(pattern=r'^[0-9a-f]{12}$')]] = Field(default_factory=list, max_length=32)

    @model_validator(mode='after')
    def canonical_evidence(self):
        from .identity import normalize_install_session_id
        normalize_install_session_id(self.installation_id)
        if len(set(self.macs)) != len(self.macs):
            raise ValueError('MAC addresses must be unique')
        return self
