import pytest
from pydantic import ValidationError

from endpoint_contracts import (
    AgentBuildRecommendationV1,
    AgentCommandAckV1,
    AgentCommandV1,
    AgentResultV1,
    DeviceIdentityV1,
    EnrollmentRequestV1,
    EnrollmentResponseV1,
)


def valid_agent_command() -> dict[str, object]:
    return {
        "schema_version": "agent_command_v1",
        "command_id": "22222222-2222-4222-8222-222222222222",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "capability": "agent.status.read",
        "parameters": {},
        "requested_by_service": "fixture-service",
        "idempotency_key": "fixture-command-01",
        "created_at": "2026-07-28T12:00:00Z",
        "deadline_at": "2026-07-28T12:05:00Z",
    }


def valid_agent_result() -> dict[str, object]:
    return {
        "schema_version": "agent_result_v1",
        "command_id": "22222222-2222-4222-8222-222222222222",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "status": "succeeded",
        "result_items": [],
        "completed_at": "2026-07-28T12:01:00Z",
    }


def test_command_rejects_deadline_not_after_creation() -> None:
    payload = valid_agent_command()
    payload["deadline_at"] = "2026-07-28T12:00:00Z"

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_unknown_shell_field() -> None:
    payload = valid_agent_command()
    payload["shell"] = "rm -rf /"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_invalid_idempotency_key() -> None:
    payload = valid_agent_command()
    payload["idempotency_key"] = "invalid key"

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_nested_non_json_parameter_value() -> None:
    payload = valid_agent_command()
    payload["parameters"] = {"nested": {"unsafe": object()}}

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_non_finite_json_parameter_value() -> None:
    payload = valid_agent_command()
    payload["parameters"] = {"timeout": float("nan")}

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_oversized_nested_json_string() -> None:
    payload = valid_agent_command()
    payload["parameters"] = {"details": {"message": "x" * 4097}}

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_oversized_nested_json_list() -> None:
    payload = valid_agent_command()
    payload["parameters"] = {"details": {"items": list(range(33))}}

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_deeply_nested_json_list() -> None:
    value: object = "leaf"
    for _ in range(9):
        value = [value]

    payload = valid_agent_command()
    payload["parameters"] = {"details": value}

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_oversized_nested_json_map() -> None:
    payload = valid_agent_command()
    payload["parameters"] = {"details": {f"key-{index}": index for index in range(33)}}

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_oversized_serialized_json() -> None:
    payload = valid_agent_command()
    payload["parameters"] = {f"key-{index}": "x" * 4096 for index in range(16)}

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_command_rejects_oversized_json_structure() -> None:
    payload = valid_agent_command()
    payload["parameters"] = {
        f"key-{index}": list(range(32)) for index in range(32)
    }

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


def test_result_rejects_more_than_32_items() -> None:
    with pytest.raises(ValidationError):
        AgentResultV1.model_validate(
            {
                "schema_version": "agent_result_v1",
                "command_id": "22222222-2222-4222-8222-222222222222",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "status": "succeeded",
                "result_items": list(range(33)),
                "completed_at": "2026-07-28T12:01:00Z",
            }
        )


def test_result_rejects_oversized_nested_json_string() -> None:
    payload = valid_agent_result()
    payload["result_items"] = [{"message": "x" * 4097}]

    with pytest.raises(ValidationError):
        AgentResultV1.model_validate(payload)


def test_result_rejects_oversized_nested_json_list() -> None:
    payload = valid_agent_result()
    payload["result_items"] = [{"items": list(range(33))}]

    with pytest.raises(ValidationError):
        AgentResultV1.model_validate(payload)


def test_result_rejects_deeply_nested_json_list() -> None:
    value: object = "leaf"
    for _ in range(9):
        value = [value]

    payload = valid_agent_result()
    payload["result_items"] = [value]

    with pytest.raises(ValidationError):
        AgentResultV1.model_validate(payload)


def test_result_rejects_oversized_nested_json_map() -> None:
    payload = valid_agent_result()
    payload["result_items"] = [{f"key-{index}": index for index in range(33)}]

    with pytest.raises(ValidationError):
        AgentResultV1.model_validate(payload)


def test_result_rejects_non_finite_json_number() -> None:
    payload = valid_agent_result()
    payload["result_items"] = [float("inf")]

    with pytest.raises(ValidationError):
        AgentResultV1.model_validate(payload)


def test_acknowledgement_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        AgentCommandAckV1.model_validate(
            {
                "schema_version": "agent_command_ack_v1",
                "command_id": "22222222-2222-4222-8222-222222222222",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "status": "shelling",
                "acknowledged_at": "2026-07-28T12:01:00Z",
            }
        )


def test_build_recommendation_rejects_non_sha256_digest() -> None:
    with pytest.raises(ValidationError):
        AgentBuildRecommendationV1.model_validate(
            {
                "schema_version": "agent_build_recommendation_v1",
                "version": "1.2.3",
                "platform": "linux",
                "artifact_path": "agent/linux/agent-1.2.3.tar.gz",
                "artifact_size_bytes": 1024,
                "sha256": "not-a-sha256",
                "minimum_launcher_version": "1.0.0",
                "channel": "stable",
                "archive_type": "tar.gz",
                "issued_at": "2026-07-28T12:01:00Z",
            }
        )


def test_build_recommendation_rejects_absolute_artifact_path() -> None:
    with pytest.raises(ValidationError):
        AgentBuildRecommendationV1.model_validate(
            {
                "schema_version": "agent_build_recommendation_v1",
                "version": "1.2.3",
                "platform": "windows",
                "artifact_path": "C:\\agent\\agent-1.2.3.zip",
                "artifact_size_bytes": 1024,
                "sha256": "a" * 64,
                "minimum_launcher_version": "1.0.0",
                "channel": "stable",
                "archive_type": "zip",
                "issued_at": "2026-07-28T12:01:00Z",
            }
        )


def test_device_identity_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        DeviceIdentityV1.model_validate(
            {
                "schema_version": "device_identity_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "platform": "linux",
                "hardware_fingerprint": "sha256:fixture",
                "shell": "rm -rf /",
            }
        )


def test_enrolment_request_requires_aware_timestamp() -> None:
    with pytest.raises(ValidationError):
        EnrollmentRequestV1.model_validate(
            {
                "schema_version": "enrollment_request_v1",
                "platform": "linux",
                "hardware_fingerprint": "sha256:fixture",
                "installation_id": "install-fixture-01",
                "requested_at": "2026-07-28T12:00:00",
            }
        )


def test_enrolment_response_requires_its_schema_version() -> None:
    response = EnrollmentResponseV1.model_validate(
        {
            "schema_version": "enrollment_response_v1",
            "device_id": "11111111-1111-4111-8111-111111111111",
            "policy_id": "policy-fixture-01",
            "enrollment_receipt": "receipt-fixture-01",
            "issued_at": "2026-07-28T12:00:00+00:00",
        }
    )

    assert response.schema_version == "enrollment_response_v1"


def test_enrolment_response_rejects_raw_device_token() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        EnrollmentResponseV1.model_validate(
            {
                "schema_version": "enrollment_response_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "policy_id": "policy-fixture-01",
                "enrollment_receipt": "receipt-fixture-01",
                "issued_at": "2026-07-28T12:00:00+00:00",
                "device_token": "raw-token-must-not-cross-enrollment-boundary",
            }
        )
