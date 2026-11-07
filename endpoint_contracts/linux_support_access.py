"""Independent Linux support adapter. Windows wire models remain unchanged."""
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from .support_access import (StrictModel, SupportRegistration, SupportStatusReport,
    canonical_public_key)

LINUX_SUPPORT_ADMIN_PATTERN = r'^[a-z_][a-z0-9_-]{0,31}$'
LinuxUID = Annotated[int, Field(strict=True, ge=0, le=2147483647)]


class LinuxSupportRegistration(SupportRegistration):
    platform: Literal['linux_amd64'] = 'linux_amd64'
    component_version: Literal['1.0.0']


class LinuxSupportStatusReport(SupportStatusReport):
    platform: Literal['linux_amd64'] = 'linux_amd64'
    component_version: Literal['1.0.0']
    installed: Annotated[bool, Field(strict=True)]
    tunnel_connected: Annotated[bool, Field(strict=True)]


class LinuxSupportPolicy(StrictModel):
    platform: Literal['linux_amd64'] = 'linux_amd64'
    device_id: UUID
    revision: int
    enabled: bool
    expires_at: datetime | None
    gateway_host: str
    gateway_port: int
    gateway_host_public_key: str
    tunnel_user: str
    remote_port: int
    local_port: Literal[22222] = 22222
    operator_public_keys: list[str]
    linux_admin_username: str | None = Field(pattern=LINUX_SUPPORT_ADMIN_PATTERN, max_length=32)
    linux_admin_uid: LinuxUID | None
    poll_after_seconds: Literal[30] = 30


class LinuxSupportPolicyUpdate(StrictModel):
    platform: Literal['linux_amd64'] = 'linux_amd64'
    enabled: Annotated[bool, Field(strict=True)]
    expires_at: datetime | None = None
    operator_public_keys: list[str] = Field(default_factory=list, max_length=16)
    linux_admin_username: str | None = Field(default=None, pattern=LINUX_SUPPORT_ADMIN_PATTERN, max_length=32)
    linux_admin_uid: LinuxUID | None = None
    reason: str = Field(min_length=3, max_length=256, pattern=r'^[^\x00-\x1f\x7f]+$')

    @field_validator('operator_public_keys')
    @classmethod
    def keys(cls, values):
        parsed = [canonical_public_key(value) for value in values]
        if len(set(parsed)) != len(parsed):
            raise ValueError('Duplicate operator key')
        return parsed

    @model_validator(mode='after')
    def paired_principal(self):
        if (self.linux_admin_username is None) != (self.linux_admin_uid is None):
            raise ValueError('Linux principal requires both exact username and UID')
        if self.enabled and self.linux_admin_username is None:
            raise ValueError('Enabled Linux policy requires an explicit principal')
        return self


class LinuxSupportRegistrationResult(StrictModel):
    device_id: UUID
    credential_id: UUID
    support_token: str = Field(repr=False)
    policy: LinuxSupportPolicy
