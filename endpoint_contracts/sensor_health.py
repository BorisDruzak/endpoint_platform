"""Bounded Agent sensor facts; the server alone derives compliance."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .base import ContractModelV1


SensorSourceStateV1 = Literal["READY", "UNAVAILABLE", "UNKNOWN"]


class PolicySensorHealthReportV1(ContractModelV1):
    schema_version: Literal["policy_sensor_health_report_v1"]
    observation_id: UUID
    policy_id: UUID
    policy_version: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)]
    observed_at: AwareDatetime
    activity_listener_state: SensorSourceStateV1
    user_sensor_last_seen_at: AwareDatetime | None = None
    security_spool_state: SensorSourceStateV1
    usb_source_state: SensorSourceStateV1
    print_source_state: SensorSourceStateV1

    @model_validator(mode="after")
    def validate_sample_time(self) -> "PolicySensorHealthReportV1":
        if (
            self.user_sensor_last_seen_at is not None
            and self.user_sensor_last_seen_at > self.observed_at + timedelta(minutes=5)
        ):
            raise ValueError("user sensor sample is after report time")
        return self


__all__ = ["PolicySensorHealthReportV1", "SensorSourceStateV1"]
