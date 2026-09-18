from __future__ import annotations

from endpoint_server.context.diff import compare_snapshots


def _snapshot(*, platform: str = "linux", model: str = "A1", storage: int = 100, interface: str = "nic:lan", version: str = "1.0") -> dict[str, object]:
    return {
        "schema_version": "device_context_v1",
        "profile": "baseline_v1",
        "sections": {
            "system": {"platform": platform, "distribution": "ALT", "architecture": "x86_64"},
            "hardware": {"manufacturer": "Acme", "model": model, "cpu_model": "CPU", "memory_bytes": 1024},
            "storage": [{"stable_key": "disk:root", "model": "Root", "size_bytes": storage}],
            "interfaces": [{"stable_key": interface, "name": "eth0", "link_type": "ethernet"}],
            "software": [{"name": "endpoint", "version": version, "source": "package"}],
        },
    }


def test_compare_snapshots_emits_only_fixed_codes_in_stable_order() -> None:
    before = _snapshot()
    after = _snapshot(platform="windows", model="A2", storage=200, interface="nic:wan", version="2.0")

    result = compare_snapshots(before, after)

    assert result.profile == "baseline_v1"
    assert [change.code for change in result.changes] == [
        "PLATFORM_CHANGED", "HARDWARE_CHANGED", "STORAGE_CHANGED", "NETWORK_CHANGED", "SOFTWARE_CHANGED"
    ]
    assert {change.code for change in result.changes} <= {
        "AGENT_CHANGED", "HARDWARE_CHANGED", "NETWORK_CHANGED", "PLATFORM_CHANGED", "SOFTWARE_CHANGED", "STORAGE_CHANGED"
    }


def test_compare_inventory_snapshots_emits_fixed_inventory_codes() -> None:
    before = {
        "profile": "inventory_v1",
        "sections": {
            "system": {"platform": "windows"},
            "hardware": {"model": "A1"},
            "memory": {"total_bytes": 8, "modules": []},
            "storage": {"physical_devices": [{"stable_key": "disk-1", "size_bytes": 100}]},
            "interfaces": [{"stable_key": "mac-aabbccddeeff", "mac": "aabbccddeeff", "name": "LAN", "link_type": "ethernet", "operational_state": "up"}],
        },
    }
    after = {
        **before,
        "sections": {
            **before["sections"],
            "hardware": {"model": "A2"},
            "memory": {"total_bytes": 16, "modules": []},
            "storage": {"physical_devices": [{"stable_key": "disk-1", "size_bytes": 200}]},
            "interfaces": [{"stable_key": "mac-aabbccddeeff", "mac": "aabbccddeeff", "name": "LAN", "link_type": "ethernet", "operational_state": "down"}],
        },
    }

    result = compare_snapshots(before, after)

    assert result.profile == "inventory_v1"
    assert [change.code for change in result.changes] == [
        "HARDWARE_CHANGED", "RAM_CHANGED", "STORAGE_CHANGED", "NETWORK_CHANGED"
    ]
