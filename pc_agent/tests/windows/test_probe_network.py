from __future__ import annotations

import json

from pc_agent.context_profiles import probe as probe_module


def test_windows_system_probe_uses_fixed_network_projection(monkeypatch) -> None:
    probe = probe_module.SystemProbe()
    monkeypatch.setattr(probe_module.os, "name", "nt")

    def fixed_run(command, timeout_seconds, max_bytes):
        assert tuple(command) == probe_module.WINDOWS_NETWORK_COMMAND
        assert timeout_seconds == 5.0
        assert max_bytes == probe_module.MAX_PROBE_BYTES
        return json.dumps({
            "interfaces": [{
                "name": "Ethernet", "mac": "00-11-22-33-44-55",
                "ipv4": ["192.0.2.10"], "ipv6": ["2001:db8::10"],
                "index": 12, "link_type": "ethernet", "operational_state": "up",
            }],
            "default_interface_index": 12,
            "default_gateway": "192.0.2.1",
        })

    monkeypatch.setattr(probe, "run", fixed_run)

    assert probe.windows_interfaces() == [{
        "name": "Ethernet", "mac": "00-11-22-33-44-55",
        "link_type": "ethernet", "operational_state": "up",
        "addresses": ["192.0.2.10", "2001:db8::10"],
    }]
    assert probe.windows_default_route() == {
        "interface": "Ethernet", "gateway": "192.0.2.1"
    }
