"""Bounded device-possession contracts; they do not authenticate a user."""
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, StringConstraints

from .base import ContractModelV1
from .enrollment import _SecretSafeContractModelV1

BindingCode = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9]{6}$")]


class DeviceBindingCreateV1(_SecretSafeContractModelV1):
    purpose: Literal["helpdesk_device_binding"]


class DeviceBindingRedeemV1(DeviceBindingCreateV1):
    _repr_secret_fields = frozenset({"code"})
    code: BindingCode


class DeviceBindingChallengeV1(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({"code", "display_code"})
    challenge_id: UUID
    code: BindingCode
    display_code: Annotated[str, StringConstraints(pattern=r"^[0-9]{3}-[0-9]{3}$")]
    expires_at: AwareDatetime
    expires_in_seconds: Literal[600]


class DeviceBindingVerifiedV1(ContractModelV1):
    status: Literal["verified"] = "verified"
    device_id: UUID
    hostname: Annotated[str, StringConstraints(max_length=256)] | None = None
    platform: Literal["windows", "linux", "unknown"] = "unknown"


class DeviceBindingErrorV1(ContractModelV1):
    """Binding routes return a bounded message, never reflected request details."""
    detail: Annotated[str, StringConstraints(max_length=64)]
