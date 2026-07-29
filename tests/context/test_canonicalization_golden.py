from __future__ import annotations

from endpoint_server.context.canonicalize import canonicalize_baseline


def test_canonical_baseline_is_deterministic_and_strips_volatile_values() -> None:
    snapshot = {
        "schema_version": "device_context_v1",
        "profile": "baseline_v1",
        "collected_at": "2026-07-29T10:00:00+00:00",
        "warnings": ["probe_unavailable"],
        "sections": {
            "system": {"architecture": "x86_64", "distribution": "ALT", "platform": "linux"},
            "hardware": {"model": "A1", "manufacturer": "Acme", "memory_bytes": 1024, "cpu_model": "CPU"},
            "storage": [
                {"stable_key": "disk:z", "model": "Z", "size_bytes": 3},
                {"stable_key": "disk:a", "model": "A", "size_bytes": 1},
            ],
            "interfaces": [{"stable_key": "nic:1", "name": "eth0", "link_type": "ethernet", "addresses": ["10.0.0.1"]}],
            "software": [{"name": "z", "version": "1", "source": "system"}, {"name": "a", "version": "1", "source": "package"}],
        },
    }

    assert canonicalize_baseline(snapshot) == {
        "schema_version": "device_context_baseline_canonical_v1",
        "profile": "baseline_v1",
        "collected_at": None,
        "sections": {
            "system": {"architecture": "x86_64", "distribution": "ALT", "platform": "linux"},
            "hardware": {"cpu_model": "CPU", "manufacturer": "Acme", "memory_bytes": 1024, "model": "A1"},
            "storage": [
                {"model": "A", "size_bytes": 1, "stable_key": "disk:a"},
                {"model": "Z", "size_bytes": 3, "stable_key": "disk:z"},
            ],
            "interfaces": [{"link_type": "ethernet", "name": "eth0", "stable_key": "nic:1"}],
            "software": [{"name": "a", "source": "package", "version": "1"}, {"name": "z", "source": "system", "version": "1"}],
        },
    }
