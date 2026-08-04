from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from pc_agent.context_profiles.registry import execute_context_capability


FIXED_TIME = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
FIXTURE = Path(__file__).parent / "fixtures" / "windows_context_profiles_v1.json"


class WindowsGoldenProbe:
    """Sanitized native Windows facts; it cannot perform network I/O."""

    platform_name = "windows"

    def windows_system(self) -> dict[str, object]:
        return {"distribution": "Windows 11 Pro", "architecture": "x86_64"}

    def windows_hardware(self) -> dict[str, object]:
        return {
            "manufacturer": "Example Systems",
            "model": "Example Workstation",
            "cpu_model": "Example CPU",
            "memory_bytes": 17179869184,
        }

    def windows_storage(self) -> list[dict[str, object]]:
        return [{"serial": "A1B2C3D4", "model": "Windows volume", "size_bytes": 512110190592}]

    def windows_interfaces(self) -> list[dict[str, object]]:
        return [{"name": "Ethernet", "mac": "00-11-22-33-44-55", "link_type": "ethernet", "addresses": ["192.0.2.10"]}]

    def windows_default_route(self) -> dict[str, object]:
        return {"interface": "Ethernet", "gateway": "192.0.2.1"}

    def windows_health(self) -> dict[str, object]:
        return {"uptime_seconds": 123, "free_bytes": 4294967296}

    def run(self, argv, timeout_seconds, max_bytes) -> str:
        assert tuple(argv) == ("tasklist", "/FO", "CSV", "/NH")
        assert timeout_seconds == 2.0
        assert max_bytes == 32768
        return '"endpoint-agent.exe","1234","Console","1","12,000 K"\n'


def _golden() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_windows_collectors_match_sanitized_golden_profile_contracts() -> None:
    """Windows native facts preserve the ALT profile envelopes and field shapes."""
    probe = WindowsGoldenProbe()
    golden = _golden()

    for capability, parameters, profile in (
        ("context.baseline.collect", {}, "baseline_v1"),
        ("context.health.collect", {}, "health_v1"),
        ("context.network.collect", {}, "network_v1"),
        ("context.diagnostic.collect", {"reason": "operator check"}, "diagnostic_v1"),
    ):
        result = execute_context_capability(capability, parameters, probe, collected_at=FIXED_TIME)

        assert result.profile == profile
        assert result.model_dump(mode="json", exclude={"collected_at"}) == golden[profile]


def test_windows_baseline_keeps_volatile_addresses_and_uptime_outside_it() -> None:
    """IP addresses, uptime, and operator diagnostics never leak into baseline."""
    result = execute_context_capability("context.baseline.collect", {}, WindowsGoldenProbe(), collected_at=FIXED_TIME)
    serialized = json.dumps(result.model_dump(mode="json"))

    assert "192.0.2.10" not in serialized
    assert "uptime_seconds" not in serialized
    assert "operator check" not in serialized
