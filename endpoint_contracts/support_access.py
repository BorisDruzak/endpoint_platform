"""Bounded independent support channel wire contract; no private SSH material."""
import base64
import binascii
import struct
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SUPPORT_RESET_DEVICE_HEADER = 'X-Support-Reset-Device'


def canonical_public_key(value: str) -> str:
    """Accept a single Ed25519 SSH key, without options, comments or newlines."""
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError('Invalid support public key')
    parts = value.split(' ')
    if len(parts) != 2 or parts[0] != 'ssh-ed25519':
        raise ValueError('Invalid support public key')
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError('Invalid support public key') from None
    expected = struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)
    if len(blob) != 51 or blob[:19] != expected or base64.b64encode(blob).decode() != parts[1]:
        raise ValueError('Invalid support public key')
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', hide_input_in_errors=True)


class SupportRegistrationConflict(StrictModel):
    detail: Literal['Support key ownership conflict'] = 'Support key ownership conflict'


class SupportRegistration(StrictModel):
    tunnel_public_key: str = Field(max_length=128, repr=False)
    host_public_key: str = Field(max_length=128, repr=False)
    component_version: str = Field(pattern=r'^\d{1,5}\.\d{1,5}\.\d{1,5}$',max_length=20)

    _keys = field_validator('tunnel_public_key','host_public_key')(canonical_public_key)

    @model_validator(mode='after')
    def distinct_roles(self):
        if self.tunnel_public_key == self.host_public_key:
            raise ValueError('Support key roles must differ')
        return self


class SupportPolicy(StrictModel):
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
    windows_admin_username: str | None
    poll_after_seconds: Literal[30] = 30


class SupportRegistrationResult(StrictModel):
    device_id: UUID
    credential_id: UUID
    support_token: str = Field(repr=False)
    policy: SupportPolicy


class SupportStatusReport(StrictModel):
    installed: bool
    tunnel_connected: bool
    last_error_code: Literal['dependency_unavailable','configuration_conflict','key_conflict','policy_unavailable','tunnel_failed','host_key_mismatch','service_failed'] | None = None

    @model_validator(mode='after')
    def installed_tunnel(self):
        if self.tunnel_connected and not self.installed:
            raise ValueError('Tunnel report requires installed support component')
        return self


class SupportPolicyUpdate(StrictModel):
    enabled: bool
    expires_at: datetime | None = None
    operator_public_keys: list[str] = Field(default_factory=list,max_length=16)
    windows_admin_username: str | None = Field(default=None,pattern=r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')
    reason: str = Field(min_length=3,max_length=256,pattern=r'^[^\x00-\x1f\x7f]+$')

    @field_validator('operator_public_keys')
    @classmethod
    def keys(cls, values):
        parsed = [canonical_public_key(key) for key in values]
        if len(set(parsed)) != len(parsed):
            raise ValueError('Duplicate operator key')
        return parsed


class SupportReason(StrictModel):
    reason: str = Field(min_length=3,max_length=256,pattern=r'^[^\x00-\x1f\x7f]+$')
