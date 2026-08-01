from __future__ import annotations

import importlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError


FIXTURE_ROOT = Path("tests/fixtures/gateway_ws")
SCHEMA_ROOT = Path("contracts/jsonschema")
DEVICE_ID = "11111111-1111-4111-8111-111111111111"
AGENT_INSTANCE_ID = "22222222-2222-4222-8222-222222222222"
SESSION_ID = "33333333-3333-4333-8333-333333333333"
COMMAND_ID = "44444444-4444-4444-8444-444444444444"


def _contracts() -> Any:
    try:
        module = importlib.import_module("endpoint_contracts.gateway_ws")
    except ModuleNotFoundError:
        pytest.fail(
            "endpoint_contracts.gateway_ws must define the Gateway WSS contract"
        )
    for name in (
        "AgentHelloV1",
        "GatewayHelloV1",
        "GatewayWsEnvelopeV1",
        "GatewayInboundV1",
    ):
        assert getattr(module, name, None) is not None, f"missing contract API: {name}"
    return module


def _agent_hello() -> dict[str, object]:
    return {
        "schema_version": "agent_hello_v1",
        "device_id": DEVICE_ID,
        "agent_instance_id": AGENT_INSTANCE_ID,
        "agent_version": "4.0.0",
        "launcher_version": "2.1.0",
        "platform": "linux_amd64",
        "boot_id": "fixture-boot-01",
        "capabilities": ["context.baseline.collect", "context.health.collect"],
        "last_result_sequence": 7,
        "last_policy_revision": 11,
    }


def _gateway_hello() -> dict[str, object]:
    return {
        "schema_version": "gateway_hello_v1",
        "session_id": SESSION_ID,
        "heartbeat_interval_seconds": 30,
        "maximum_message_bytes": 65536,
        "policy_revision": 12,
        "effective_capabilities": ["context.baseline.collect"],
        "server_time": "2026-08-01T07:30:00Z",
    }


def _command() -> dict[str, object]:
    return {
        "schema_version": "agent_command_v1",
        "command_id": COMMAND_ID,
        "device_id": DEVICE_ID,
        "capability": "context.baseline.collect",
        "parameters": {},
        "requested_by_service": "endpoint-gateway",
        "idempotency_key": "gateway-command-01",
        "created_at": "2026-08-01T07:30:00Z",
        "deadline_at": "2026-08-01T07:35:00Z",
    }


def _envelope(
    kind: str, payload: dict[str, object], *, sequence: int = 1
) -> dict[str, object]:
    return {
        "schema_version": "gateway_ws_envelope_v1",
        "kind": kind,
        "sequence": sequence,
        "payload": payload,
    }


def _payloads_by_kind() -> dict[str, dict[str, object]]:
    return {
        "agent_hello": _agent_hello(),
        "gateway_hello": _gateway_hello(),
        "heartbeat": {
            "schema_version": "agent_heartbeat_v1",
            "device_id": DEVICE_ID,
            "platform": "linux",
            "agent_version": "4.0.0",
            "reported_at": "2026-08-01T07:30:05Z",
        },
        "command": _command(),
        "command_ack": {
            "schema_version": "agent_command_ack_v1",
            "command_id": COMMAND_ID,
            "device_id": DEVICE_ID,
            "status": "acknowledged",
            "acknowledged_at": "2026-08-01T07:30:10Z",
            "message": "Command accepted.",
        },
        "command_result": {
            "schema_version": "agent_result_v1",
            "command_id": COMMAND_ID,
            "device_id": DEVICE_ID,
            "status": "succeeded",
            "result_items": [{"summary": "Fixture result."}],
            "message": "Command completed.",
            "completed_at": "2026-08-01T07:30:20Z",
        },
        "command_cancel": {
            "schema_version": "command_cancel_v1",
            "command_id": COMMAND_ID,
            "reason": "operator_requested",
            "canceled_at": "2026-08-01T07:30:15Z",
        },
        "result_ack": {
            "schema_version": "result_ack_v1",
            "command_id": COMMAND_ID,
            "result_sequence": 7,
        },
        "policy_update": {
            "schema_version": "policy_update_v1",
            "policy_revision": 12,
            "effective_capabilities": ["context.baseline.collect"],
        },
        "server_shutdown_notice": {
            "schema_version": "server_shutdown_notice_v1",
            "reason": "server_restart",
            "retry_after_seconds": 10,
        },
        "error": {
            "schema_version": "gateway_error_v1",
            "code": "invalid_message",
            "message": "The message did not match the gateway contract.",
            "retryable": False,
        },
    }


def test_agent_hello_is_strict_frozen_and_serializes_canonically() -> None:
    contracts = _contracts()
    hello = contracts.AgentHelloV1.model_validate(_agent_hello())

    assert hello.model_dump(mode="json") == _agent_hello()
    with pytest.raises(ValidationError):
        hello.boot_id = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("agent_version", "x" * 129),
        ("launcher_version", "x" * 129),
        ("boot_id", "x" * 129),
        ("capabilities", [f"capability.{index}" for index in range(65)]),
        ("last_result_sequence", -1),
        ("last_policy_revision", -1),
        ("last_result_sequence", "7"),
    ],
)
def test_agent_hello_rejects_oversized_or_noncanonical_values(
    field_name: str, invalid_value: object
) -> None:
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.AgentHelloV1.model_validate(
            {**_agent_hello(), field_name: invalid_value}
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("ticket_id", "ticket-1"),
        ("job_id", "job-1"),
        ("target_url", "https://untrusted.example.test/run"),
        ("executable", "powershell.exe"),
        ("arguments", ["-Command", "whoami"]),
    ],
)
def test_agent_hello_rejects_ticket_url_and_executable_extensions(
    field_name: str, value: object
) -> None:
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.AgentHelloV1.model_validate({**_agent_hello(), field_name: value})


def test_gateway_hello_requires_timezone_and_bounded_positive_limits() -> None:
    contracts = _contracts()
    hello = contracts.GatewayHelloV1.model_validate(_gateway_hello())
    assert hello.server_time.isoformat() == "2026-08-01T07:30:00+00:00"

    invalid_values = {
        "server_time": "2026-08-01T07:30:00",
        "heartbeat_interval_seconds": 0,
        "maximum_message_bytes": 0,
        "policy_revision": -1,
    }
    for field_name, invalid_value in invalid_values.items():
        with pytest.raises(ValidationError):
            contracts.GatewayHelloV1.model_validate(
                {**_gateway_hello(), field_name: invalid_value}
            )


@pytest.mark.parametrize("kind", tuple(_payloads_by_kind()))
def test_envelope_accepts_every_declared_kind(kind: str) -> None:
    contracts = _contracts()
    envelope = _envelope(kind, _payloads_by_kind()[kind])

    parsed = contracts.GatewayWsEnvelopeV1.model_validate(envelope)

    assert (
        parsed.model_dump(mode="json", exclude_unset=True, exclude_none=True)
        == envelope
    )


def test_envelope_rejects_unknown_kind_unknown_fields_and_negative_sequence() -> None:
    contracts = _contracts()
    valid = _envelope("command", _command())

    invalid_envelopes = [
        {**valid, "kind": "invoke_service"},
        {**valid, "ticket_id": "ticket-1"},
        {**valid, "target_url": "https://untrusted.example.test/run"},
        {**valid, "sequence": -1},
        {**valid, "sequence": "1"},
    ]
    for envelope in invalid_envelopes:
        with pytest.raises(ValidationError):
            contracts.GatewayWsEnvelopeV1.model_validate(envelope)


def test_envelope_rejects_mismatched_payload_and_oversized_control_data() -> None:
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.GatewayWsEnvelopeV1.model_validate(
            _envelope("command", _gateway_hello())
        )

    error = _payloads_by_kind()["error"]
    with pytest.raises(ValidationError):
        contracts.GatewayWsEnvelopeV1.model_validate(
            _envelope("error", {**error, "message": "x" * 513})
        )


def test_command_envelope_rejects_executable_capabilities_and_extensions() -> None:
    contracts = _contracts()
    command = _command()

    with pytest.raises(ValidationError):
        contracts.GatewayWsEnvelopeV1.model_validate(
            _envelope("command", {**command, "capability": "shell.execute"})
        )
    with pytest.raises(ValidationError):
        contracts.GatewayWsEnvelopeV1.model_validate(
            _envelope("command", {**command, "executable": "powershell.exe"})
        )
    for parameters in (
        {"target_url": "https://untrusted.example.test/run"},
        {"executable": "powershell.exe", "arguments": ["-Command", "whoami"]},
    ):
        with pytest.raises(ValidationError):
            contracts.GatewayWsEnvelopeV1.model_validate(
                _envelope("command", {**command, "parameters": parameters})
            )


def test_gateway_inbound_is_the_server_to_agent_subset() -> None:
    contracts = _contracts()
    command = _envelope("command", _command())

    parsed = contracts.GatewayInboundV1.model_validate(command)
    assert (
        parsed.model_dump(mode="json", exclude_unset=True, exclude_none=True) == command
    )

    with pytest.raises(ValidationError):
        contracts.GatewayInboundV1.model_validate(
            _envelope("agent_hello", _agent_hello())
        )


@pytest.mark.parametrize(
    ("schema_name", "payload"),
    [
        ("agent_hello_v1.json", _agent_hello()),
        ("gateway_hello_v1.json", _gateway_hello()),
        ("gateway_ws_envelope_v1.json", _envelope("command", _command())),
    ],
)
def test_committed_json_schemas_validate_canonical_payloads(
    schema_name: str, payload: dict[str, object]
) -> None:
    _contracts()
    schema = json.loads((SCHEMA_ROOT / schema_name).read_text(encoding="utf-8"))

    Draft202012Validator(schema).validate(payload)


def test_envelope_json_schema_enforces_kind_bounds_and_neutrality() -> None:
    _contracts()
    schema = json.loads(
        (SCHEMA_ROOT / "gateway_ws_envelope_v1.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    valid = _envelope("command", _command())

    invalid_envelopes = [
        {**valid, "kind": "invoke_service"},
        {**valid, "sequence": -1},
        {**valid, "ticket_id": "ticket-1"},
        {**valid, "target_url": "https://untrusted.example.test/run"},
        _envelope("command", {**_command(), "executable": "powershell.exe"}),
        _envelope(
            "command",
            {**_command(), "parameters": {"executable": "powershell.exe"}},
        ),
    ]
    for envelope in invalid_envelopes:
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(envelope)


@pytest.mark.parametrize(
    ("fixture_name", "model_name"),
    [
        ("agent_hello_v1.json", "AgentHelloV1"),
        ("gateway_hello_v1.json", "GatewayHelloV1"),
        ("gateway_ws_envelope_v1.json", "GatewayWsEnvelopeV1"),
    ],
)
def test_golden_serialization_fixture_matches_model(
    fixture_name: str, model_name: str
) -> None:
    contracts = _contracts()
    payload = json.loads((FIXTURE_ROOT / fixture_name).read_text(encoding="utf-8"))
    model = getattr(contracts, model_name)

    assert (
        model.model_validate(deepcopy(payload)).model_dump(
            mode="json", exclude_unset=True, exclude_none=True
        )
        == payload
    )
