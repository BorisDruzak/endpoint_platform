from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest


FIXED_TIME = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)


class FakeProbe:
    """Deterministic local-host probe; it deliberately has no network API."""

    def __init__(self) -> None:
        self.network_connect_calls: list[object] = []
        self.reads: list[tuple[str, int]] = []
        self.commands: list[tuple[tuple[str, ...], float, int]] = []
        self.text = {
            "/etc/os-release": 'PRETTY_NAME="ALT Linux"\n',
            "/sys/class/dmi/id/sys_vendor": "Example Systems\n",
            "/sys/class/dmi/id/product_name": "Workstation\n",
            "/proc/cpuinfo": "model name : Example CPU\n",
            "/proc/meminfo": "MemTotal:        8388608 kB\nMemAvailable:    4194304 kB\n",
            "/proc/uptime": "123.4 50.0\n",
            "/proc/loadavg": "0.50 0.25 0.10 1/100 1\n",
        }
        self.outputs = {
            ("lsblk", "--bytes", "--json", "--output", "NAME,MODEL,SIZE,WWN,SERIAL,TYPE"): json.dumps(
                {
                    "blockdevices": [
                        {
                            "name": "sda",
                            "model": "Example SSD",
                            "size": 512110190592,
                            "wwn": "0x5000c500aabbccdd",
                            "serial": "SERIAL-01",
                            "type": "disk",
                        }
                    ]
                }
            ),
            ("ip", "-json", "link", "show"): json.dumps(
                [
                    {
                        "ifname": "eth0",
                        "address": "00:11:22:33:44:55",
                        "link_type": "ether",
                    }
                ]
            ),
            ("ip", "-json", "route", "show", "default"): json.dumps(
                [{"dev": "eth0", "gateway": "192.0.2.1"}]
            ),
            ("ip", "-json", "address", "show"): json.dumps(
                [{"ifname": "eth0", "addr_info": [{"local": "192.0.2.10"}]}]
            ),
            ("systemctl", "is-active", "sshd"): "active\n",
            ("systemctl", "is-active", "NetworkManager"): "inactive\n",
            ("ps", "-eo", "comm=,stat="): "agent S\nworker R\n",
            ("journalctl", "-n", "100", "--no-pager", "-o", "cat"): "token=super-secret\nservice healthy\n",
        }

    def read_text(self, path: str, max_bytes: int) -> str:
        self.reads.append((path, max_bytes))
        return self.text.get(path, "")[:max_bytes]

    def run(self, argv: list[str] | tuple[str, ...], timeout_seconds: float, max_bytes: int) -> str:
        command = tuple(argv)
        self.commands.append((command, timeout_seconds, max_bytes))
        return self.outputs.get(command, "")[:max_bytes]


@pytest.fixture
def fake_probe() -> FakeProbe:
    return FakeProbe()
