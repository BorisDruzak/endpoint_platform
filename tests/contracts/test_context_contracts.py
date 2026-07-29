import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from endpoint_contracts import DeviceContextEnvelopeV1, validate_context_result_item


FIXTURES_ROOT = Path(__file__).parents[1] / "fixtures" / "context"


def baseline_fixture(platform: str = "alt") -> dict[str, object]:
    return json.loads((FIXTURES_ROOT / platform / "baseline_v1.json").read_text())


def test_context_accepts_anonymized_alt_and_windows_baselines() -> None:
    """A profile-specific envelope preserves only bounded stable facts."""
    assert DeviceContextEnvelopeV1.model_validate(baseline_fixture()).profile == "baseline_v1"
    assert (
        DeviceContextEnvelopeV1.model_validate(baseline_fixture("windows")).sections.system.platform
        == "windows"
    )


def test_context_rejects_unknown_or_volatile_fields() -> None:
    """Volatile facts cannot enter the canonical baseline envelope or sections."""
    with pytest.raises(ValidationError):
        DeviceContextEnvelopeV1.model_validate({**baseline_fixture(), "uptime": 10})
    with pytest.raises(ValidationError):
        DeviceContextEnvelopeV1.model_validate(
            {
                **baseline_fixture(),
                "sections": {**baseline_fixture()["sections"], "uptime": 10},
            }
        )


def test_context_rejects_payload_device_identity_and_unknown_warning_code() -> None:
    """Transport binds the device; payloads expose only fixed public warnings."""
    with pytest.raises(ValidationError):
        DeviceContextEnvelopeV1.model_validate(
            {**baseline_fixture(), "device_id": "11111111-1111-4111-8111-111111111111"}
        )
    with pytest.raises(ValidationError):
        DeviceContextEnvelopeV1.model_validate(
            {**baseline_fixture(), "warnings": ["unbounded_agent_message"]}
        )


def test_context_result_requires_known_profile() -> None:
    """Agent result items cannot select arbitrary context schemas."""
    with pytest.raises(ValidationError):
        validate_context_result_item(
            {"schema_version": "device_context_v1", "profile": "arbitrary"}
        )


def test_context_result_helper_returns_only_the_validated_envelope() -> None:
    """Result validation does not retain arbitrary result-item wrapper data."""
    envelope = validate_context_result_item({**baseline_fixture(), "warnings": ["source_unavailable"]})

    assert isinstance(envelope, DeviceContextEnvelopeV1)
    assert envelope.model_dump(mode="json") == {
        **baseline_fixture(),
        "warnings": ["source_unavailable"],
    }
