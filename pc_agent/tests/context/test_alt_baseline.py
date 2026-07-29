from __future__ import annotations

from pc_agent.context_profiles.baseline import collect_baseline

from .conftest import FIXED_TIME


def test_alt_baseline_prefers_wwn_and_normalized_mac_stable_keys(fake_probe) -> None:
    """Changing disk display text cannot replace a real WWN or interface MAC key."""
    result = collect_baseline(fake_probe, collected_at=FIXED_TIME)

    assert result.profile == "baseline_v1"
    assert result.sections.system.distribution == "ALT Linux"
    assert result.sections.storage[0].stable_key == "wwn-0x5000c500aabbccdd"
    assert result.sections.interfaces[0].stable_key == "mac-001122334455"


def test_alt_baseline_is_a_strict_contract_envelope(fake_probe) -> None:
    """The collector returns the profile contract, not an inventory-shaped payload."""
    result = collect_baseline(fake_probe, collected_at=FIXED_TIME)

    assert result.schema_version == "device_context_v1"
    assert result.collected_at == FIXED_TIME
