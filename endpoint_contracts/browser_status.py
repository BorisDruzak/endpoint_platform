"""Strict Agent-observed browser facts; overall compliance belongs to server."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .base import ContractModelV1


BrowserFamilyV1 = Literal["chrome", "yandex"]
BrowserStateV1 = Literal["DETECTED", "ABSENT", "UNKNOWN"]
BrowserRunningStateV1 = Literal["RUNNING", "CLOSED", "UNKNOWN"]
BrowserPolicyOwnerV1 = Literal["ENDPOINT", "EXTERNAL", "NONE", "CONFLICT", "UNKNOWN"]
BrowserInstallationPolicyStateV1 = Literal[
    "APPLIED", "NOT_APPLIED", "CONFLICT", "UNKNOWN"
]
NativeHostStateV1 = Literal["READY", "MISSING", "UNKNOWN"]
ExtensionVersionV1 = Annotated[
    str | None, Field(strict=True, min_length=1, max_length=32, pattern=r"^[0-9]+(?:\.[0-9]+){1,3}$")
]


class BrowserFamilyStatusV1(ContractModelV1):
    browser_family: BrowserFamilyV1
    browser_state: BrowserStateV1
    running_state: BrowserRunningStateV1
    policy_owner: BrowserPolicyOwnerV1
    installation_policy_state: BrowserInstallationPolicyStateV1
    native_host_state: NativeHostStateV1
    extension_version: ExtensionVersionV1 = None
    extension_last_seen_at: AwareDatetime | None = None
    last_running_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_facts(self) -> "BrowserFamilyStatusV1":
        if self.browser_state == "ABSENT" and self.running_state == "RUNNING":
            raise ValueError("absent browser cannot be running")
        if self.running_state == "RUNNING" and self.last_running_at is None:
            raise ValueError("running browser requires last_running_at")
        if (self.extension_version is None) != (self.extension_last_seen_at is None):
            raise ValueError("extension version and last seen time must agree")
        if self.policy_owner == "CONFLICT" and self.installation_policy_state != "CONFLICT":
            raise ValueError("policy owner conflict requires conflict state")
        return self


class BrowserStatusReportV1(ContractModelV1):
    schema_version: Literal["browser_status_report_v1"]
    observation_id: UUID
    policy_id: UUID
    policy_version: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)]
    observed_at: AwareDatetime
    browsers: list[BrowserFamilyStatusV1] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def validate_report(self) -> "BrowserStatusReportV1":
        if {item.browser_family for item in self.browsers} != {"chrome", "yandex"}:
            raise ValueError("one status for each supported browser is required")
        latest = self.observed_at + timedelta(minutes=5)
        for item in self.browsers:
            if item.extension_last_seen_at is not None and item.extension_last_seen_at > latest:
                raise ValueError("extension heartbeat is after report time")
            if item.last_running_at is not None and item.last_running_at > latest:
                raise ValueError("browser running time is after report time")
        return self


__all__ = ["BrowserFamilyStatusV1", "BrowserStatusReportV1"]
