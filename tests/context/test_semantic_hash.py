from __future__ import annotations

from endpoint_server.context.canonicalize import canonicalize_baseline, canonicalize_inventory
from endpoint_server.context.semantic_hash import semantic_hash


def _baseline(*, collected_at: str, warnings: list[str], address: str, storage_order: bool) -> dict[str, object]:
    storage = [
        {"stable_key": "disk:data", "model": "Data", "size_bytes": 200},
        {"stable_key": "disk:root", "model": "Root", "size_bytes": 100},
    ]
    if storage_order:
        storage.reverse()
    return {
        "schema_version": "device_context_v1",
        "profile": "baseline_v1",
        "collected_at": collected_at,
        "warnings": warnings,
        "sections": {
            "system": {"platform": "linux", "distribution": "ALT", "architecture": "x86_64"},
            "hardware": {"manufacturer": "Acme", "model": "A1", "cpu_model": "CPU", "memory_bytes": 1024},
            "storage": storage,
            "interfaces": [
                {"stable_key": "nic:lan", "name": "eth0", "link_type": "ethernet", "addresses": [address]}
            ],
            "software": [
                {"name": "endpoint", "version": "1.0", "source": "package"},
                {"name": "kernel", "version": "6.0", "source": "system"},
            ],
        },
    }


def test_hash_ignores_observation_timestamp_warning_address_and_list_order() -> None:
    first = _baseline(
        collected_at="2026-07-29T10:00:00+00:00",
        warnings=[],
        address="192.168.1.10",
        storage_order=False,
    )
    later = _baseline(
        collected_at="2026-07-29T11:00:00+00:00",
        warnings=["probe_unavailable"],
        address="10.0.0.10",
        storage_order=True,
    )

    assert canonicalize_baseline(first)["collected_at"] is None
    assert semantic_hash(canonicalize_baseline(first)) == semantic_hash(canonicalize_baseline(later))


def test_hash_changes_for_material_network_identity_change() -> None:
    first = _baseline(
        collected_at="2026-07-29T10:00:00+00:00", warnings=[], address="192.168.1.10", storage_order=False
    )
    changed = _baseline(
        collected_at="2026-07-29T10:00:00+00:00", warnings=[], address="192.168.1.10", storage_order=False
    )
    changed["sections"]["interfaces"][0]["stable_key"] = "nic:wan"  # type: ignore[index]

    assert semantic_hash(canonicalize_baseline(first)) != semantic_hash(canonicalize_baseline(changed))


def test_inventory_hash_ignores_timestamp_warnings_addresses_and_order() -> None:
    first = {
        "profile": "inventory_v1", "collected_at": "2026-01-01T00:00:00Z", "warnings": [],
        "sections": {"system": {"hostname": "host", "platform": "windows"}, "hardware": {"model": "A"},
                     "memory": {"total_bytes": 8, "modules": [{"slot": "B"}, {"slot": "A"}]},
                     "storage": {"physical_devices": [{"stable_key": "disk-b"}, {"stable_key": "disk-a"}]},
                     "interfaces": [{"stable_key": "mac-aabbccddeeff", "ipv4": ["192.0.2.1"]}]},
    }
    later = {**first, "collected_at": "2026-01-02T00:00:00Z", "warnings": ["probe_unavailable"]}
    later["sections"] = {**first["sections"], "memory": {"total_bytes": 8, "modules": [{"slot": "A"}, {"slot": "B"}]}, "storage": {"physical_devices": [{"stable_key": "disk-a"}, {"stable_key": "disk-b"}]}, "interfaces": [{"stable_key": "mac-aabbccddeeff", "ipv4": ["10.0.0.1"]}]}

    assert semantic_hash(canonicalize_inventory(first)) == semantic_hash(canonicalize_inventory(later))
