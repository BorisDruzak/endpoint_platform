from uuid import uuid4

import pytest
from pydantic import ValidationError


def test_result_is_bounded_and_security_ids_are_exact_unique_nonempty():
    from endpoint_contracts.telemetry_results import TelemetryResultV1
    payload = dict(schema_version="telemetry_result_v1", report_kind="security_event_batch", report_id=uuid4(),
                   report_sequence=7, disposition="rejected", reason_code="outside_policy", event_identifiers=[uuid4()])
    assert TelemetryResultV1(**payload).report_sequence == 7
    for changes in ({"report_sequence": -1}, {"reason_code": "contains private detail"},
                    {"reason_code": "a" * 65}, {"event_identifiers": []},
                    {"event_identifiers": payload["event_identifiers"] * 2},
                    {"report_kind": "activity_observation"}):
        with pytest.raises(ValidationError):
            TelemetryResultV1(**(payload | changes))


def test_gateway_hello_omits_empty_protocol_features_even_when_nested():
    from endpoint_contracts.gateway_ws import GatewayHelloV1, GatewayHelloEnvelopeV1
    from tests.contracts.test_gateway_ws_contract import _gateway_hello
    hello = GatewayHelloV1.model_validate(_gateway_hello())
    assert hello.protocol_features == []
    frame = GatewayHelloEnvelopeV1(schema_version="gateway_ws_envelope_v1", sequence=0, kind="gateway_hello", payload=hello)
    assert "protocol_features" not in frame.model_dump(mode="json")["payload"]
