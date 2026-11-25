"""Typed maintenance of one existing printer on a device's local scheduler."""

from typing import Annotated, Literal

from pydantic import ConfigDict, Field, StrictBool, field_validator, model_validator

from .base import ContractModelV1


CUPS_QUEUE_CONFIGURE = "printer.cups.queue.configure"
CUPS_TEST_PAGE_SUBMIT = "printer.cups.testpage.submit"
CupsCapabilityV1 = Literal["printer.cups.queue.configure", "printer.cups.testpage.submit"]
CupsQueueName = Annotated[str, Field(
    strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$",
    json_schema_extra={"not": {"pattern": r"^[aA][lL][lL]$"}},
)]
CupsSwitch = Literal["keep", "on", "off"]


class CupsTestPageParametersV1(ContractModelV1):
    queue: CupsQueueName

    @field_validator("queue")
    @classmethod
    def validate_destination(cls, queue: str) -> str:
        if queue.lower() == "all":
            raise ValueError("a single CUPS destination is required")
        return queue


class CupsQueueConfigureParametersV1(CupsTestPageParametersV1):
    model_config = ConfigDict(json_schema_extra={"anyOf": [
        {"required": [field], "properties": {field: {"enum": ["on", "off"]}}}
        for field in ("enabled", "accepting")
    ]})

    enabled: CupsSwitch = "keep"
    accepting: CupsSwitch = "keep"

    @model_validator(mode="after")
    def validate_change(self) -> "CupsQueueConfigureParametersV1":
        if self.enabled == self.accepting == "keep":
            raise ValueError("an explicit CUPS queue setting is required")
        return self


CUPS_ACTION_PARAMETERS = {
    CUPS_QUEUE_CONFIGURE: CupsQueueConfigureParametersV1,
    CUPS_TEST_PAGE_SUBMIT: CupsTestPageParametersV1,
}


class CupsQueueStateV1(ContractModelV1):
    enabled: StrictBool
    accepting: StrictBool


class CupsActionResultV1(ContractModelV1):
    schema_version: Literal["cups_action_result_v1"] = "cups_action_result_v1"
    capability: CupsCapabilityV1
    queue: CupsQueueName
    outcome: Literal["configured", "submitted", "rejected", "unknown"]
    before: CupsQueueStateV1 | None = None
    after: CupsQueueStateV1 | None = None
    job_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}-[1-9][0-9]{0,9}$")] | None = None
    error_code: Literal[
        "cups_unavailable", "cups_queue_unavailable", "cups_queue_rejecting",
        "cups_local_journal_unavailable", "cups_request_conflict",
        "cups_deadline_expired", "cups_outcome_unknown",
    ] | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> "CupsActionResultV1":
        if self.outcome == "configured":
            if self.capability != CUPS_QUEUE_CONFIGURE or self.before is None or self.after is None:
                raise ValueError("queue configuration requires the before and after state")
        if self.outcome == "submitted":
            if (
                self.capability != CUPS_TEST_PAGE_SUBMIT or not self.job_id
                or self.job_id.rsplit("-", 1)[0].lower() != self.queue.lower()
            ):
                raise ValueError("test page submission requires the destination's job ID")
        elif self.job_id is not None:
            raise ValueError("a job ID is only available for an accepted submission")
        if (self.error_code is not None) != (self.outcome in {"rejected", "unknown"}):
            raise ValueError("unsuccessful CUPS outcomes require an error code")
        return self
