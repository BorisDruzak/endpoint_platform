import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BeforeValidator, Field

from .base import ContractModelV1


_HARDWARE_FINGERPRINT_PATTERN = re.compile(
    r"^sha256:[a-z0-9][a-z0-9._-]{1,248}$",
    re.ASCII,
)
_MAX_INSTALL_SESSION_LENGTH = 128


def normalize_hardware_fingerprint(value: object) -> str:
    """Return the canonical enrollment fingerprint or reject unstructured text.

    The wire representation is a lower-case ``sha256:`` identifier of 8--256
    ASCII characters.  Lower-casing makes an operator-provided provisioning
    claim and the agent enrollment request hash the same durable binding.
    """
    if not isinstance(value, str):
        raise ValueError("hardware fingerprint must be a string")
    canonical = value.lower()
    if not _HARDWARE_FINGERPRINT_PATTERN.fullmatch(canonical):
        raise ValueError("hardware fingerprint must be canonical sha256 identifier")
    return canonical


def normalize_install_session_id(value: object) -> str:
    """Return the exact bounded installation binding or reject unsafe text.

    Installation session IDs are proof material, not operator prose.  They
    retain their wire representation so the provisioning service and first-boot
    agent bind the same bytes without silent normalization.
    """
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_INSTALL_SESSION_LENGTH
        or value != value.strip()
        or not value.isascii()
        or any(not 32 <= ord(character) <= 126 for character in value)
    ):
        raise ValueError("install session ID must be bounded printable ASCII")
    return value


HardwareFingerprintV1 = Annotated[
    str,
    Field(min_length=8, max_length=256, pattern=_HARDWARE_FINGERPRINT_PATTERN.pattern),
    BeforeValidator(normalize_hardware_fingerprint),
]


class DeviceIdentityV1(ContractModelV1):
    schema_version: Literal["device_identity_v1"]
    device_id: UUID
    platform: Literal["linux", "windows"]
    hardware_fingerprint: HardwareFingerprintV1


class AgentSessionV1(ContractModelV1):
    schema_version: Literal["agent_session_v1"]
    device_id: UUID
    session_id: UUID
    issued_at: AwareDatetime
    expires_at: AwareDatetime
