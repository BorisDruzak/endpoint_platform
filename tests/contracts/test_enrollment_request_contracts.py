from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from endpoint_contracts import (
    PreEnrollmentRequestCreateV1,
    WindowsEnrollmentPolicyV1,
)
from endpoint_server.enrollment.campaigns import parse_windows_enrollment_policy


def _policy() -> dict[str, object]:
    return {
        "policy_id": "windows-office-v1",
        "enrollment_mode": "auto",
        "allowed_installer_releases": ["1.0.0"],
    }


def _request() -> dict[str, object]:
    return {
        "schema_version": "pre_enrollment_request_create_v1",
        "platform": "windows",
        "installation_id": "win-00112233-4455-6677-8899-aabbccddeeff",
        "hardware_fingerprint": "sha256:windows-fingerprint-v1",
        "request_capability": "a" * 43,
        "installer_version": "1.0.0",
        "installer_release_id": "1.0.0",
        "requested_at": datetime.now(UTC),
        "hostname": "office-pc-01",
        "manufacturer": "Contoso",
        "model": "Workstation",
        "serial": "SYS-001",
        "product_uuid": "d3d7a3f9-9876-4a8e-9ecf-1234567890ab",
        "macs": ["aabbccddeeff"],
    }


def test_windows_policy_accepts_explicit_auto_mode_and_release() -> None:
    policy = WindowsEnrollmentPolicyV1.model_validate(_policy())

    assert policy.enrollment_mode == "auto"
    assert parse_windows_enrollment_policy(_policy()) == policy


@pytest.mark.parametrize(
    "invalid",
    [
        {"policy_id": "windows-office-v1", "allowed_installer_releases": ["1.0.0"]},
        {**_policy(), "allowed_installer_releases": ["1.0.0", "1.0.0"]},
        {**_policy(), "enrollment_mode": "automatic"},
    ],
)
def test_windows_policy_rejects_ambiguous_or_invalid_configuration(
    invalid: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        WindowsEnrollmentPolicyV1.model_validate(invalid)


def test_public_request_is_windows_only_and_forbids_campaign_selection() -> None:
    request = PreEnrollmentRequestCreateV1.model_validate(_request())

    assert request.platform == "windows"
    with pytest.raises(ValidationError):
        PreEnrollmentRequestCreateV1.model_validate({**_request(), "campaign_id": "x"})
    with pytest.raises(ValidationError):
        PreEnrollmentRequestCreateV1.model_validate({**_request(), "platform": "linux"})


def test_public_request_rejects_unbounded_evidence() -> None:
    with pytest.raises(ValidationError):
        PreEnrollmentRequestCreateV1.model_validate(
            {**_request(), "hostname": "a" * 257}
        )
