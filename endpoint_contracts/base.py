from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, field_validator


class ContractModelV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("*", mode="after")
    @classmethod
    def normalize_protocol_datetimes(cls, value: object) -> object:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc)
        return value
