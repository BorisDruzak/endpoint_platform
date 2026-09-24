"""Bounded, content-free observation from an interactive user session."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import ContractModelV1


ActivityStateV1 = Literal["ACTIVE", "IDLE", "LOCKED", "DISCONNECTED", "UNKNOWN"]
ApplicationCategoryV1 = Literal["browser", "office", "business_app", "system", "remote_access", "other"]
BrowserFamilyV1 = Literal["chrome", "yandex"]
BrowserSensorStateV1 = Literal["NOT_APPLICABLE", "NEVER_SEEN", "ACTIVE", "STALE", "ERROR"]
_PROCESS_NAME = re.compile(r"^[^\\/\x00-\x1f:]{1,128}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")


class ForegroundApplicationV1(ContractModelV1):
    process_name: Annotated[str, Field(strict=True, min_length=1, max_length=128,
                                       pattern=r"^[^\\/\x00-\x1f:]+$")]
    application_category: ApplicationCategoryV1

    @field_validator("process_name")
    @classmethod
    def validate_process_name(cls, value: str) -> str:
        if not _PROCESS_NAME.fullmatch(value) or value != value.strip():
            raise ValueError("foreground must contain only a process name")
        return value


class BrowserActivityV1(ContractModelV1):
    browser_family: BrowserFamilyV1
    origin: Annotated[str | None, Field(strict=True, max_length=512,
                                        pattern=r"^https?://[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?$")] = None
    domain: Annotated[str | None, Field(strict=True, max_length=253,
                                        pattern=r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")] = None
    sensor_state: BrowserSensorStateV1
    extension_version: Annotated[str | None, Field(strict=True, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")] = None
    last_seen_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_origin(self) -> "BrowserActivityV1":
        if (self.origin is None) != (self.domain is None):
            raise ValueError("browser origin and domain must be present together")
        if self.origin is None:
            return self
        parsed = urlsplit(self.origin)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment
            or self.origin != f"{parsed.scheme}://{parsed.netloc}"
            or parsed.hostname != self.domain
            or self.domain != self.domain.lower()
            or not _DOMAIN.fullmatch(self.domain)
        ):
            raise ValueError("browser context must contain only a normalized origin and domain")
        try:
            if parsed.port == 0:
                raise ValueError("invalid browser origin port")
        except ValueError as error:
            raise ValueError("invalid browser origin port") from error
        return self


class ActivitySectionsV1(ContractModelV1):
    user_login: Annotated[str | None, Field(strict=True, max_length=256,
                                            pattern=r"^[^\x00-\x1f]+$")] = None
    session_state: ActivityStateV1
    idle_seconds: Annotated[int | None, Field(strict=True, ge=0, le=86400)] = None
    foreground: ForegroundApplicationV1 | None = None
    browser: BrowserActivityV1 | None = None

    @model_validator(mode="after")
    def validate_state(self) -> "ActivitySectionsV1":
        if self.session_state in {"ACTIVE", "IDLE"}:
            if self.idle_seconds is None:
                raise ValueError("active session needs idle seconds")
        elif self.idle_seconds is not None or self.foreground is not None:
            raise ValueError("non-interactive session cannot report idle or foreground")
        return self


class ActivityObservationV1(ActivitySectionsV1):
    schema_version: Literal["activity_observation_v1"]
    observation_id: UUID
    observed_at: AwareDatetime


__all__ = [
    "ActivityObservationV1", "ActivitySectionsV1", "ActivityStateV1",
    "BrowserActivityV1", "ForegroundApplicationV1",
]
