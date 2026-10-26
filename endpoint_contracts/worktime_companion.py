"""Closed credential-free user interaction and Core-only HTTPS delivery contracts."""
from datetime import date
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from .base import ContractModelV1

CAPABILITY = 'endpoint.worktime-companion.v1'


class CompanionPollV1(ContractModelV1):
    schema_version: Literal['worktime_companion_poll_v1'] = 'worktime_companion_poll_v1'
    capability: Literal['endpoint.worktime-companion.v1'] = CAPABILITY


class CompanionActionV1(ContractModelV1):
    schema_version: Literal['worktime_companion_action_v1'] = 'worktime_companion_action_v1'
    request_id: UUID
    lease_id: UUID
    action: Literal['present', 'failed', 'displayed', 'reason', 'later']


class CompanionReplyV1(ContractModelV1):
    schema_version: Literal['worktime_companion_reply_v1'] = 'worktime_companion_reply_v1'
    capability: Literal['endpoint.worktime-companion.v1'] = CAPABILITY
    request_id: UUID | None = None
    lease_id: UUID | None = None
    day: date | None = None
    portal_url: str | None = Field(default=None, max_length=2048)

    @field_validator('portal_url')
    @classmethod
    def safe_url(cls, value):
        if value is not None:
            from urllib.parse import urlsplit, parse_qs
            parsed = urlsplit(value)
            query = parse_qs(parsed.query, strict_parsing=True)
            if (parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password
                    or parsed.fragment or parsed.path != '/employee'
                    or set(query) != {'day', 'request_id'}
                    or len(query['day']) != 1 or len(query['request_id']) != 1):
                raise ValueError('Invalid WorkTime portal URL')
            date.fromisoformat(query['day'][0])
            UUID(query['request_id'][0])
        return value

    @model_validator(mode='after')
    def match_request(self):
        if self.portal_url is not None:
            from urllib.parse import urlsplit, parse_qs
            query = parse_qs(urlsplit(self.portal_url).query)
            if self.request_id is None or UUID(query['request_id'][0]) != self.request_id:
                raise ValueError('Portal request does not match notification')
            if self.day is None or query['day'][0] != self.day.isoformat():
                raise ValueError('Portal day does not match notification')
        return self


class CompanionDevicePollV1(CompanionPollV1):
    # Set by Core using authenticated local OS facts; never read from local JSON.
    user_login: str = Field(min_length=1, max_length=256)


class CompanionDeviceActionV1(CompanionActionV1):
    user_login: str = Field(min_length=1, max_length=256)
