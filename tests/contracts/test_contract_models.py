from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from endpoint_contracts import (
    AgentUpdateAcknowledgementV1,
    AgentUpdateRecommendationV1,
    AgentUpdateReportV1,
    AgentBuildRecommendationV1,
    AgentCommandAckV1,
    AgentCommandV1,
    AgentEnrollmentDeliveryV1,
    AgentEnrollmentRequestV1,
    AgentHeartbeatV1,
    AgentResultV1,
    AgentSessionV1,
    DeviceIdentityV1,
    DeviceCredentialRotationV1,
    EnrollmentDeliveryProofV1,
    EnrollmentRequestV1,
    EnrollmentResponseV1,
    UpdateBuildManifestV1,
    UpdateRolloutCreateV1,
)


VALID_UPDATE_BUILD = {
    "schema_version": "update_build_manifest_v1",
    "build_identifier": "endpoint-agent-linux-1.2.3",
    "version": "1.2.3",
    "platform": "linux_amd64",
    "channel": "stable",
    "artifact_url": "https://releases.example.test/endpoint-agent-1.2.3.tar.gz",
    "artifact_name": "endpoint-agent-1.2.3.tar.gz",
    "archive_type": "tar.gz",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "size": 1024,
}

VALID_UPDATE_REPORT = {
    "schema_version": "agent_update_report_v1",
    "report_key": "report-fixture-01",
    "status": "applied",
    "reported_version": "1.2.3",
}


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


def test_update_build_manifest_rejects_non_https_and_bad_digest() -> None:
    """Reject a manifest that could bypass verified artifact delivery."""
    with pytest.raises(ValidationError):
        UpdateBuildManifestV1.model_validate(
            {**VALID_UPDATE_BUILD, "artifact_url": "http://bad.example.test/agent"}
        )
    with pytest.raises(ValidationError):
        UpdateBuildManifestV1.model_validate({**VALID_UPDATE_BUILD, "sha256": "ABC"})


def test_update_build_manifest_rejects_unknown_or_unsafe_artifact_fields() -> None:
    """Reject raw local paths and unrecognised manifest extensions."""
    with pytest.raises(ValidationError):
        UpdateBuildManifestV1.model_validate(
            {**VALID_UPDATE_BUILD, "archive_path": r"C:\\releases\\agent.zip"}
        )
    with pytest.raises(ValidationError):
        UpdateBuildManifestV1.model_validate(
            {
                **VALID_UPDATE_BUILD,
                "artifact_url": "https://user:pass@example.test/agent",
            }
        )


def test_update_rollout_requires_deduplicated_explicit_device_targets() -> None:
    """Reject duplicate device assignments before a rollout is persisted."""
    payload = {
        "schema_version": "update_rollout_v1",
        "build_identifier": "endpoint-agent-linux-1.2.3",
        "mode": "canary",
        "device_ids": [
            "11111111-1111-4111-8111-111111111111",
            "11111111-1111-4111-8111-111111111111",
        ],
    }

    with pytest.raises(ValidationError):
        UpdateRolloutCreateV1.model_validate(payload)


def test_agent_update_recommendation_exposes_only_verified_manifest_metadata() -> None:
    """Keep recommendation payloads free of device credentials and local paths."""
    recommendation = AgentUpdateRecommendationV1.model_validate(
        {
            "schema_version": "agent_update_recommendation_v1",
            "operation_id": "55555555-5555-4555-8555-555555555555",
            **{
                key: value
                for key, value in VALID_UPDATE_BUILD.items()
                if key != "schema_version"
            },
            "reason": "canary rollout",
        }
    )

    assert str(recommendation.operation_id) == "55555555-5555-4555-8555-555555555555"
    with pytest.raises(ValidationError):
        AgentUpdateRecommendationV1.model_validate(
            {
                **recommendation.model_dump(mode="json"),
                "device_token": "secret-device-token",
            }
        )


def test_agent_update_acknowledgement_accepts_only_nonterminal_progress() -> None:
    """Prevent an acknowledgement from claiming a launcher outcome."""
    accepted = AgentUpdateAcknowledgementV1.model_validate(
        {"schema_version": "agent_update_ack_v1", "status": "scheduled"}
    )

    assert accepted.status == "scheduled"
    with pytest.raises(ValidationError):
        AgentUpdateAcknowledgementV1.model_validate(
            {"schema_version": "agent_update_ack_v1", "status": "applied"}
        )


def test_agent_update_report_excludes_raw_diagnostics() -> None:
    """Reject traceback/log fields so opaque diagnostics cannot reach storage."""
    with pytest.raises(ValidationError):
        AgentUpdateReportV1.model_validate(
            {**VALID_UPDATE_REPORT, "traceback": "secret"}
        )


def test_agent_update_report_bounds_safe_details_and_terminal_statuses() -> None:
    """Reject unbounded messages and nonterminal state reports."""
    report = AgentUpdateReportV1.model_validate(
        {
            **VALID_UPDATE_REPORT,
            "status": "rolled_back",
            "safe_code": "launcher_verify_failed",
            "safe_message": "Version verification failed after restart.",
        }
    )

    assert report.status == "rolled_back"
    with pytest.raises(ValidationError):
        AgentUpdateReportV1.model_validate(
            {**VALID_UPDATE_REPORT, "status": "scheduled"}
        )
    with pytest.raises(ValidationError):
        AgentUpdateReportV1.model_validate(
            {**VALID_UPDATE_REPORT, "safe_message": "x" * 513}
        )


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


@pytest.mark.parametrize("capability", ["agent.status.read", "gateway.echo"])
def test_command_accepts_only_documented_safe_v1_capabilities(
    capability: str,
) -> None:
    payload = valid_agent_command()
    payload["capability"] = capability

    command = AgentCommandV1.model_validate(payload)

    assert command.capability == capability


@pytest.mark.parametrize(
    "capability",
    [
        "shell.execute",
        "python",
        "powershell",
        "routeros",
        "scheme",
        "custom.action",
    ],
)
def test_command_rejects_executable_or_unallowlisted_capabilities(
    capability: str,
) -> None:
    payload = valid_agent_command()
    payload["capability"] = capability

    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(payload)


@pytest.mark.parametrize(
    ("model", "payload", "field_name", "offset_value", "expected"),
    [
        (
            AgentSessionV1,
            {
                "schema_version": "agent_session_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "session_id": "22222222-2222-4222-8222-222222222222",
                "issued_at": "2026-07-28T17:00:00+05:00",
                "expires_at": "2026-07-28T17:05:00+05:00",
            },
            "issued_at",
            "2026-07-28T17:00:00+05:00",
            datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        ),
        (
            AgentSessionV1,
            {
                "schema_version": "agent_session_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "session_id": "22222222-2222-4222-8222-222222222222",
                "issued_at": "2026-07-28T17:00:00+05:00",
                "expires_at": "2026-07-28T17:05:00+05:00",
            },
            "expires_at",
            "2026-07-28T17:05:00+05:00",
            datetime(2026, 7, 28, 12, 5, tzinfo=timezone.utc),
        ),
        (
            EnrollmentRequestV1,
            {
                "schema_version": "enrollment_request_v1",
                "platform": "linux",
                "hardware_fingerprint": "sha256:fixture",
                "installation_id": "install-fixture-01",
                "requested_at": "2026-07-28T17:00:00+05:00",
            },
            "requested_at",
            "2026-07-28T17:00:00+05:00",
            datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        ),
        (
            EnrollmentResponseV1,
            {
                "schema_version": "enrollment_response_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "policy_id": "policy-fixture-01",
                "enrollment_receipt": "receipt-fixture-01",
                "issued_at": "2026-07-28T17:00:00+05:00",
            },
            "issued_at",
            "2026-07-28T17:00:00+05:00",
            datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        ),
        (
            AgentCommandV1,
            {
                **valid_agent_command(),
                "created_at": "2026-07-28T17:00:00+05:00",
                "deadline_at": "2026-07-28T17:05:00+05:00",
            },
            "created_at",
            "2026-07-28T17:00:00+05:00",
            datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        ),
        (
            AgentCommandV1,
            {
                **valid_agent_command(),
                "created_at": "2026-07-28T17:00:00+05:00",
                "deadline_at": "2026-07-28T17:05:00+05:00",
            },
            "deadline_at",
            "2026-07-28T17:05:00+05:00",
            datetime(2026, 7, 28, 12, 5, tzinfo=timezone.utc),
        ),
        (
            AgentCommandAckV1,
            {
                "schema_version": "agent_command_ack_v1",
                "command_id": "22222222-2222-4222-8222-222222222222",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "status": "acknowledged",
                "acknowledged_at": "2026-07-28T17:00:00+05:00",
            },
            "acknowledged_at",
            "2026-07-28T17:00:00+05:00",
            datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        ),
        (
            AgentResultV1,
            {
                **valid_agent_result(),
                "completed_at": "2026-07-28T17:00:00+05:00",
            },
            "completed_at",
            "2026-07-28T17:00:00+05:00",
            datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        ),
        (
            AgentHeartbeatV1,
            {
                "schema_version": "agent_heartbeat_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "platform": "linux",
                "agent_version": "1.2.3",
                "reported_at": "2026-07-28T17:00:00+05:00",
            },
            "reported_at",
            "2026-07-28T17:00:00+05:00",
            datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        ),
        (
            AgentBuildRecommendationV1,
            {
                "schema_version": "agent_build_recommendation_v1",
                "version": "1.2.3",
                "platform": "linux",
                "artifact_path": "agent/linux/agent-1.2.3.tar.gz",
                "artifact_size_bytes": 1024,
                "sha256": "a" * 64,
                "minimum_launcher_version": "1.0.0",
                "channel": "stable",
                "archive_type": "tar.gz",
                "issued_at": "2026-07-28T17:00:00+05:00",
            },
            "issued_at",
            "2026-07-28T17:00:00+05:00",
            datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        ),
    ],
)
def test_protocol_datetimes_normalize_non_utc_offsets_to_utc(
    model: type,
    payload: dict[str, object],
    field_name: str,
    offset_value: str,
    expected: datetime,
) -> None:
    assert payload[field_name] == offset_value

    contract = model.model_validate(payload)

    assert getattr(contract, field_name) == expected
    assert getattr(contract, field_name).tzinfo is timezone.utc
    assert contract.model_dump(mode="json")[field_name] == expected.isoformat().replace(
        "+00:00", "Z"
    )


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
    payload["parameters"] = {f"key-{index}": list(range(32)) for index in range(32)}

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


def test_build_recommendation_rejects_artifact_path_with_trailing_newline() -> None:
    with pytest.raises(ValidationError):
        AgentBuildRecommendationV1.model_validate(
            {
                "schema_version": "agent_build_recommendation_v1",
                "version": "1.2.3",
                "platform": "windows",
                "artifact_path": "agent/agent.zip\n",
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


def test_agent_enrollment_transport_models_are_strict_and_secret_aware() -> None:
    request = AgentEnrollmentRequestV1.model_validate(
        {
            "schema_version": "agent_enrollment_request_v1",
            "platform": "linux",
            "hardware_fingerprint": "sha256:fixture",
            "installation_id": "install-fixture-01",
            "delivery_nonce": "A" * 43,
            "requested_at": "2026-07-29T17:00:00+05:00",
        }
    )
    delivery = AgentEnrollmentDeliveryV1.model_validate(
        {
            "schema_version": "agent_enrollment_delivery_v1",
            "device_id": "11111111-1111-4111-8111-111111111111",
            "policy_id": "policy-fixture-01",
            "policy": {"channel": "stable"},
            "enrollment_receipt": "B" * 43,
            "device_token": "C" * 43,
            "issued_at": "2026-07-29T17:00:00+05:00",
        }
    )
    proof = EnrollmentDeliveryProofV1.model_validate(
        {
            "schema_version": "enrollment_delivery_proof_v1",
            "enrollment_receipt": "B" * 43,
            "hardware_fingerprint": "sha256:fixture",
        }
    )
    rotation = DeviceCredentialRotationV1.model_validate(
        {
            "schema_version": "device_credential_rotation_v1",
            "device_token": "D" * 43,
            "overlap_expires_at": "2026-07-29T17:10:00+05:00",
        }
    )

    assert request.requested_at.isoformat() == "2026-07-29T12:00:00+00:00"
    assert delivery.issued_at.isoformat() == "2026-07-29T12:00:00+00:00"
    assert proof.enrollment_receipt == "B" * 43
    assert rotation.overlap_expires_at.isoformat() == "2026-07-29T12:10:00+00:00"
    assert "A" * 43 not in repr(request)
    assert "B" * 43 not in repr(delivery)
    assert "C" * 43 not in repr(delivery)
    assert "D" * 43 not in repr(rotation)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            AgentEnrollmentRequestV1,
            {
                "schema_version": "agent_enrollment_request_v1",
                "platform": "linux",
                "hardware_fingerprint": "sha256:fixture",
                "installation_id": "install-fixture-01",
                "delivery_nonce": "short",
                "requested_at": "2026-07-29T12:00:00Z",
            },
        ),
        (
            AgentEnrollmentDeliveryV1,
            {
                "schema_version": "enrollment_response_v1",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "policy_id": "policy-fixture-01",
                "policy": {},
                "enrollment_receipt": "B" * 43,
                "device_token": "C" * 43,
                "issued_at": "2026-07-29T12:00:00Z",
            },
        ),
        (
            EnrollmentDeliveryProofV1,
            {
                "schema_version": "enrollment_delivery_proof_v1",
                "enrollment_receipt": "!" * 43,
                "hardware_fingerprint": "sha256:fixture",
            },
        ),
        (
            DeviceCredentialRotationV1,
            {
                "schema_version": "device_credential_rotation_v1",
                "device_token": "D" * 44,
                "overlap_expires_at": "2026-07-29T12:10:00Z",
            },
        ),
    ],
)
def test_agent_enrollment_transport_rejects_invalid_secret_shapes(
    model: type[object],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)
