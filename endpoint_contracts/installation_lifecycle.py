"""Source-bound native installation facts. Presence is never installation authority."""
from typing import Annotated, Literal
from uuid import UUID
from pydantic import AwareDatetime, Field, model_validator
from .base import ContractModelV1

Sequence = Annotated[int, Field(strict=True, ge=1, le=2147483647)]


class InstallationNativeProof(ContractModelV1):
    version: str = Field(pattern=r'^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$', max_length=17)
    product_code: str = Field(pattern=r'^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$', max_length=38)
    source_revision: str = Field(pattern=r'^[0-9a-f]{40}$', max_length=40)
    msi_sha256: str = Field(pattern=r'^[0-9a-f]{64}$', max_length=64)
    exit_code: Annotated[int, Field(strict=True, ge=0, le=0)]


class InstallationCleanup(ContractModelV1):
    support: Literal['complete', 'incomplete', 'not_applicable']
    browser: Literal['complete', 'external_preserved', 'conflict', 'failed', 'not_applicable']


class InstallationEventV1(ContractModelV1):
    schema_version: Literal['endpoint_installation_event_v1']
    device_id: UUID
    event_id: UUID
    generation_id: UUID
    sequence: Sequence
    previous_event_id: UUID | None
    action: Literal['installed', 'removed']
    occurred_at: AwareDatetime
    native: InstallationNativeProof
    cleanup: InstallationCleanup

    @model_validator(mode='after')
    def causal_predecessor(self):
        if (self.sequence == 1) != (self.previous_event_id is None):
            raise ValueError('Only the first event has no predecessor')
        if self.event_id == self.previous_event_id:
            raise ValueError('An event cannot precede itself')
        return self


class InstallationEventAckV1(ContractModelV1):
    schema_version: Literal['endpoint_installation_event_ack_v1']
    device_id: UUID
    event_id: UUID
    generation_id: UUID
    sequence: Sequence
    state: Literal['installed', 'removed']
    received_at: AwareDatetime
