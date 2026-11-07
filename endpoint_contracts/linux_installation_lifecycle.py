"""Exact RPM input proof on the shared causal installation stream."""
from typing import Annotated, Literal

from pydantic import Field, model_validator
from .base import ContractModelV1
from .installation_lifecycle import InstallationEventV1

NEVRA_PATTERN = r'^[A-Za-z0-9][A-Za-z0-9+_.:-]{2,190}\.x86_64$'


class LinuxNativeSource(ContractModelV1):
    version: str = Field(pattern=r'^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$', max_length=17)
    source_revision: str = Field(pattern=r'^[0-9a-f]{40}$', max_length=40)
    core_nevra: str = Field(pattern=NEVRA_PATTERN, max_length=200)
    core_rpm_sha256: str = Field(pattern=r'^[0-9a-f]{64}$', max_length=64)
    user_sensor_nevra: str | None = Field(default=None, pattern=NEVRA_PATTERN, max_length=200)
    user_sensor_rpm_sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$', max_length=64)

    @model_validator(mode='after')
    def paired_sensor(self):
        if (self.user_sensor_nevra is None) != (self.user_sensor_rpm_sha256 is None):
            raise ValueError('UserSensor native input requires both NEVRA and archive digest')
        return self


class LinuxInstallationNativeProof(LinuxNativeSource):
    exit_code: Annotated[int, Field(strict=True, ge=0, le=0)]


class LinuxInstallationEventV1(InstallationEventV1):
    schema_version: Literal['endpoint_linux_installation_event_v1']
    native: LinuxInstallationNativeProof
