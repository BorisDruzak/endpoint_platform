from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from .base import ContractModelV1


class DeviceIdentityV1(ContractModelV1):
    schema_version: Literal["device_identity_v1"]
    device_id: UUID
    platform: Literal["linux", "windows"]
    hardware_fingerprint: Annotated[str, Field(min_length=8, max_length=256)]


class AgentSessionV1(ContractModelV1):
    schema_version: Literal["agent_session_v1"]
    device_id: UUID
    session_id: UUID
    issued_at: AwareDatetime
    expires_at: AwareDatetime
