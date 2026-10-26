from datetime import UTC, datetime
from uuid import uuid4
import json
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from endpoint_contracts.power_events import (
    PowerEventV1,
    PowerEventBatchV1,
    PowerEventAckV1,
    PowerSourceStatusV1,
)
from endpoint_server.gateway.protocol import parse_agent_envelope, GatewayProtocolError
from tests.power.test_power_provider import batch, event


def test_schema_rejects_invalid_evidence_relationships():
    validator = Draft202012Validator(
        PowerEventV1.model_json_schema(), format_checker=FormatChecker()
    )
    valid = event().model_dump(mode="json")
    validator.validate(valid)
    for changes in (
        {"event_kind": "OS_STARTED", "evidence": "request"},
        {"event_kind": "OS_UNEXPECTED_SHUTDOWN_REPORTED", "evidence": "transition"},
        {"event_kind": "OS_STARTED", "sleep_subtype": "hibernate"},
    ):
        with pytest.raises(ValidationError):
            validator.validate(valid | changes)


def test_power_parser_direction_and_payload_byte_bound():
    body = batch(
        [
            event().model_copy(
                update={
                    "event_identifier": uuid4(),
                    "native_record_id": "x" * 128,
                    "boot_id": "b" * 128,
                    "source": "s" * 128,
                }
            )
            for _ in range(128)
        ]
    ).model_dump(mode="json")
    frame = dict(
        schema_version="gateway_ws_envelope_v1",
        kind="power_event_batch",
        sequence=1,
        payload=body,
    )
    with pytest.raises(GatewayProtocolError, match="message_too_large"):
        parse_agent_envelope(json.dumps(frame), maximum_message_bytes=1024 * 1024)
    frame.update(
        kind="power_event_ack",
        payload=dict(
            schema_version="power_event_ack_v1",
            batch_id=str(uuid4()),
            persisted_at=datetime.now(UTC).isoformat(),
            results=[],
        ),
    )
    with pytest.raises(GatewayProtocolError, match="invalid_direction"):
        parse_agent_envelope(json.dumps(frame), maximum_message_bytes=1024 * 1024)


def test_all_power_schemas_are_valid_and_ack_dispositions_exact_unique():
    for model in (
        PowerEventV1,
        PowerEventBatchV1,
        PowerEventAckV1,
        PowerSourceStatusV1,
    ):
        Draft202012Validator.check_schema(model.model_json_schema())
    valid = dict(
        event_identifier=uuid4(), disposition="accepted", reason_code="persisted"
    )
    from pydantic import ValidationError as PydanticError

    with pytest.raises(PydanticError):
        PowerEventAckV1(
            schema_version="power_event_ack_v1",
            batch_id=uuid4(),
            persisted_at=datetime.now(UTC),
            results=[valid, valid],
        )
