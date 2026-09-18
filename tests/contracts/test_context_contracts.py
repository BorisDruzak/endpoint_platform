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


def inventory_fixture() -> dict[str, object]:
    return {
        "schema_version": "device_context_v1",
        "profile": "inventory_v1",
        "collected_at": "2026-09-18T00:00:00Z",
        "warnings": [],
        "sections": {
            "system": {
                "hostname": "office-pc-01",
                "platform": "windows",
                "os_name": "Windows",
                "os_version": "11",
                "os_build": "26100",
                "architecture": "x86_64",
            },
            "hardware": {
                "manufacturer": "Contoso",
                "model": "Workstation",
                "serial_number": "SYS-001",
                "product_uuid": "d3d7a3f9-9876-4a8e-9ecf-1234567890ab",
                "cpu_model": "CPU 9000",
                "bios_vendor": None,
                "bios_version": None,
                "baseboard_manufacturer": None,
                "baseboard_model": None,
                "baseboard_serial": None,
            },
            "memory": {
                "total_bytes": 17179869184,
                "memory_type": "DDR4",
                "module_count": 2,
                "modules": [
                    {
                        "slot": "DIMM A1",
                        "manufacturer": "Contoso",
                        "part_number": "RAM-8G",
                        "serial": "RAM-001",
                        "capacity_bytes": 8589934592,
                        "speed_mt_s": 2666,
                        "memory_type": "DDR4",
                    }
                ],
            },
            "storage": {
                "physical_devices": [
                    {
                        "stable_key": "disk-serial-001",
                        "model": "SSD 980",
                        "serial": "DISK-001",
                        "size_bytes": 500107862016,
                        "media_type": "SSD",
                        "bus_type": "NVME",
                    }
                ]
            },
            "interfaces": [
                {
                    "name": "Ethernet",
                    "stable_key": "mac-aabbccddeeff",
                    "mac": "aabbccddeeff",
                    "ipv4": ["192.168.100.10"],
                    "ipv6": ["fe80::1"],
                    "link_type": "ethernet",
                    "operational_state": "up",
                }
            ],
        },
    }


def test_context_accepts_strict_inventory_with_canonical_mac_key() -> None:
    envelope = DeviceContextEnvelopeV1.model_validate(inventory_fixture())

    assert envelope.profile == "inventory_v1"
    assert envelope.sections.interfaces[0].stable_key == "mac-aabbccddeeff"


def test_inventory_context_rejects_secret_field_and_mismatched_mac_key() -> None:
    secret = inventory_fixture()
    secret["sections"]["hardware"]["token"] = "forbidden"  # type: ignore[index]
    with pytest.raises(ValidationError):
        DeviceContextEnvelopeV1.model_validate(secret)

    invalid_key = inventory_fixture()
    invalid_key["sections"]["interfaces"][0]["stable_key"] = "interface-ethernet"  # type: ignore[index]
    with pytest.raises(ValidationError):
        DeviceContextEnvelopeV1.model_validate(invalid_key)


def test_context_accepts_session_without_interactive_user() -> None:
    envelope = DeviceContextEnvelopeV1.model_validate(
        {
            "schema_version": "device_context_v1",
            "profile": "session_v1",
            "collected_at": "2026-09-18T00:00:00Z",
            "sections": {
                "current_user_login": None,
                "interactive_session_present": False,
            },
            "warnings": [],
        }
    )

    assert envelope.profile == "session_v1"
