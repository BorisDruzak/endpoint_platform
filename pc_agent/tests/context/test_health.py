from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from pc_agent.context_profiles.health import collect_health
from pc_agent.context_profiles.probe import SystemProbe, UPDATE_PATH_STATUS_COMMAND, UPDATE_SERVICE_STATUS_COMMAND

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


def test_linux_health_distinguishes_idle_updater_from_active_watch(fake_probe) -> None:
    fake_probe.outputs[UPDATE_SERVICE_STATUS_COMMAND] = "LoadState=loaded\nActiveState=inactive\n"
    fake_probe.outputs[UPDATE_PATH_STATUS_COMMAND] = "LoadState=loaded\nActiveState=active\n"
    services = {item.name: item.status for item in collect_health(fake_probe).sections.services}
    assert services["endpoint-agent-update.service"] == "inactive"
    assert services["endpoint-agent-update.path"] == "active"

    fake_probe.outputs[UPDATE_SERVICE_STATUS_COMMAND] = "LoadState=not-found\nActiveState=inactive\n"
    services = {item.name: item.status for item in collect_health(fake_probe).sections.services}
    assert services["endpoint-agent-update.service"] == "unknown"


@pytest.mark.parametrize(("native", "expected"), [
    (4, "active"), (1, "inactive"), (2, "unknown"), (None, "unknown"),
])
def test_windows_health_maps_only_observed_service_state(monkeypatch, native, expected) -> None:
    closed = []

    class ScmError(Exception):
        pass

    def open_manager(machine, database, rights):
        assert (machine, database, rights) == (None, None, 1)
        return "scm"

    def open_service(manager, name, rights):
        assert (manager, name, rights) == ("scm", "EndpointAgentUpdater", 4)
        return "updater"

    def query(service):
        assert service == "updater"
        if native is None:
            raise ScmError("query failed")
        return (0, native, 0, 0, 0, 0, 0)

    monkeypatch.setitem(sys.modules, "pywintypes", SimpleNamespace(error=ScmError))
    monkeypatch.setitem(sys.modules, "win32service", SimpleNamespace(
        SC_MANAGER_CONNECT=1, SERVICE_QUERY_STATUS=4, SERVICE_RUNNING=4, SERVICE_STOPPED=1,
        OpenSCManager=open_manager, OpenService=open_service, QueryServiceStatus=query,
        CloseServiceHandle=closed.append,
    ))
    probe = SimpleNamespace(
        platform_name="windows", windows_health=lambda: {"uptime_seconds": 10, "free_bytes": 4096},
        windows_updater_status=SystemProbe().windows_updater_status,
    )
    services = collect_health(probe, collected_at=FIXED_TIME).sections.services
    assert [(item.name, item.status) for item in services] == [("EndpointAgentUpdater", expected)]
    assert closed == ["updater", "scm"]
