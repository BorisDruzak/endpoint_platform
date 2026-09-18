from __future__ import annotations

from pc_agent.context_profiles.inventory import collect_inventory
from pc_agent.tests.context.conftest import FIXED_TIME


def test_alt_inventory_collects_physical_facts_and_canonical_mac(fake_probe) -> None:
    fake_probe.text.update(
        {
            "/sys/class/dmi/id/product_serial": "SYS-001\n",
            "/sys/class/dmi/id/product_uuid": "11111111-2222-3333-4444-555555555555\n",
            "/sys/class/dmi/id/board_vendor": "Example Board\n",
            "/sys/class/dmi/id/board_name": "Board X\n",
            "/sys/class/dmi/id/board_serial": "BOARD-001\n",
        }
    )

    result = collect_inventory(fake_probe, collected_at=FIXED_TIME)

    assert result.profile == "inventory_v1"
    assert result.sections.hardware.serial_number == "SYS-001"
    assert result.sections.hardware.product_uuid == "11111111-2222-3333-4444-555555555555"
    assert result.sections.memory.total_bytes == 8589934592
    assert result.sections.storage.physical_devices[0].model == "Example SSD"
    assert result.sections.storage.physical_devices[0].media_type == "SSD"
    assert result.sections.storage.physical_devices[0].bus_type == "SATA"
    assert result.sections.interfaces[0].stable_key == "mac-001122334455"
    assert result.sections.interfaces[0].mac == "001122334455"


def test_alt_inventory_returns_null_optional_dmi_data_with_safe_warning(fake_probe) -> None:
    result = collect_inventory(fake_probe, collected_at=FIXED_TIME)

    assert result.sections.hardware.serial_number is None
    assert result.sections.hardware.product_uuid is None
    assert "source_unavailable" in result.warnings
