"""Public Console projections; no agent or Windows wire changes."""
from datetime import datetime
from typing import Literal
from uuid import UUID
from .support_access import StrictModel
from .linux_support_access import LinuxSupportPolicy, LinuxUID, LINUX_SUPPORT_ADMIN_PATTERN
from pydantic import Field


class SupportPlatform(StrictModel):
    device_id: UUID
    platform: Literal['linux_amd64', 'windows_amd64'] | None


class LinuxSupportConfiguredPolicy(StrictModel):
    enabled: bool
    expires_at: datetime | None
    operator_public_keys: list[str]
    linux_admin_username: str | None = Field(pattern=LINUX_SUPPORT_ADMIN_PATTERN, max_length=32)
    linux_admin_uid: LinuxUID | None


class LinuxSupportAdminStatus(StrictModel):
    policy: LinuxSupportPolicy
    configured_policy: LinuxSupportConfiguredPolicy
    component_version: str
    installed: bool
    tunnel_connected: bool
    reported_at: datetime | None
    last_error_code: str | None
    host_public_key: str
    access_verified_at: datetime | None
    access_verified_by: str | None
    verification_kind: Literal['operator_attestation']
    revoked_at: datetime | None
    reset_registration_allowed: bool
