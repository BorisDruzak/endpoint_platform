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
        "platform_changed", "hardware_changed", "storage_changed", "network_changed", "software_changed"
    ]
    assert {change.code for change in result.changes} <= {
        "agent_changed", "hardware_changed", "network_changed", "platform_changed", "software_changed", "storage_changed"
    }
