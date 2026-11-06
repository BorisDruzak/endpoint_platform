"""Bounded independent support channel wire contract; no private SSH material."""
import base64
import binascii
import re
import struct
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SUPPORT_RESET_DEVICE_HEADER = 'X-Support-Reset-Device'
SUPPORT_COMPONENT_VERSION_PATTERN = r'^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$'
WINDOWS_SUPPORT_ADMIN_PATTERN = r'^(?:[A-Za-z0-9][A-Za-z0-9_-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'
WINDOWS_SUPPORT_ADMIN_DESCRIPTION = (
    'Existing local SAM or explicit NETBIOSDOMAIN\\SAM, ASCII only, at most 64 characters total. '
    'The NetBIOS domain is at most 15 characters. Explicit domain principals are normalized to lowercase; '
    'local names retain compatibility. The device verifies the exact existing administrator SID. '
    'UPN, DNS aliases, spaces, wildcards and SSH configuration characters are not accepted.'
)


def normalize_windows_support_admin(value: str) -> str:
    if len(value)>64 or re.fullmatch(WINDOWS_SUPPORT_ADMIN_PATTERN, value, flags=re.ASCII) is None:
        raise ValueError('Invalid existing Windows administrator principal')
    return value.lower() if '\\' in value else value


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
    windows_admin_username: str | None = Field(max_length=64,pattern=WINDOWS_SUPPORT_ADMIN_PATTERN,
                                               description=WINDOWS_SUPPORT_ADMIN_DESCRIPTION)
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
    component_version: str | None = Field(default=None,max_length=17,pattern=SUPPORT_COMPONENT_VERSION_PATTERN,
        description='Compiled version reported by the running Support service. Omitted legacy reports mean 1.0.0; installer registration is not runtime attestation.')

    @field_validator('component_version')
    @classmethod
    def runtime_version(cls,value):
        if value is not None and re.fullmatch(SUPPORT_COMPONENT_VERSION_PATTERN,value,flags=re.ASCII) is None:
            raise ValueError('Invalid Support runtime version')
        return value

    @model_validator(mode='after')
    def installed_tunnel(self):
        if self.tunnel_connected and not self.installed:
            raise ValueError('Tunnel report requires installed support component')
        return self


class SupportPolicyUpdate(StrictModel):
    enabled: bool
    expires_at: datetime | None = None
    operator_public_keys: list[str] = Field(default_factory=list,max_length=16)
    windows_admin_username: str | None = Field(default=None,max_length=64,pattern=WINDOWS_SUPPORT_ADMIN_PATTERN,
                                               description=WINDOWS_SUPPORT_ADMIN_DESCRIPTION)
    reason: str = Field(min_length=3,max_length=256,pattern=r'^[^\x00-\x1f\x7f]+$')

    @field_validator('operator_public_keys')
    @classmethod
    def keys(cls, values):
        parsed = [canonical_public_key(key) for key in values]
        if len(set(parsed)) != len(parsed):
            raise ValueError('Duplicate operator key')
        return parsed

    @field_validator('windows_admin_username')
    @classmethod
    def existing_principal(cls, value):
        return None if value is None else normalize_windows_support_admin(value)


class SupportReason(StrictModel):
    reason: str = Field(min_length=3,max_length=256,pattern=r'^[^\x00-\x1f\x7f]+$')
