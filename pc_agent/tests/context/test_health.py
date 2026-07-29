from __future__ import annotations

from pc_agent.context_profiles.health import collect_health

from .conftest import FIXED_TIME


def test_health_maps_optional_service_probe_failure_to_fixed_warning(fake_probe) -> None:
    """A failed optional service probe leaves a valid health envelope."""
    original_run = fake_probe.run

    def failing_run(argv, timeout_seconds, max_bytes):
        if tuple(argv) == ("systemctl", "is-active", "NetworkManager"):
            raise TimeoutError("not surfaced")
        return original_run(argv, timeout_seconds, max_bytes)

    fake_probe.run = failing_run
    result = collect_health(fake_probe, collected_at=FIXED_TIME)

    assert result.profile == "health_v1"
    assert "command_timed_out" in result.warnings
    assert result.sections.resources.free_bytes == 4294967296
