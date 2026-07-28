import pytest
from pydantic import ValidationError

from endpoint_contracts import (
    DeviceIdentityV1,
    EnrollmentRequestV1,
    EnrollmentResponseV1,
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
