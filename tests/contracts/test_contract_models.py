import pytest
from pydantic import ValidationError

from endpoint_contracts import DeviceIdentityV1, EnrollmentRequestV1


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
