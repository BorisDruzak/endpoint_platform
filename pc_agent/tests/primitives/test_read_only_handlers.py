"""Behavior tests for fixed, privacy-safe Endpoint diagnostics."""

from __future__ import annotations

import socket
import sys
from datetime import UTC, datetime
from types import SimpleNamespace

from endpoint_contracts import AgentCommandV1
from endpoint_contracts.read_only_primitives import (
    AdapterListParametersV1,
    RouteGetParametersV1,
    ServiceStatusParametersV1,
)
from pc_agent.primitives.network.policy import AgentNetworkProbePolicy, NetworkProbeDenied
from pc_agent.primitives.read_only.command_execution import execute_read_only_agent_command
from pc_agent.primitives.read_only.handlers import (
    _linux_service_details,
    _resolve_candidates,
    adapter_list,
    route_get,
    service_status,
)


NOW = datetime(2026, 8, 28, tzinfo=UTC)


def _route_parameters() -> RouteGetParametersV1:
    return RouteGetParametersV1(
        schema_version="route_get_parameters_v1",
        target="router.example.test",
        port=443,
        family="ipv4",
        timeout_ms=1000,
    )


def test_route_get_policy_checks_every_resolved_candidate_before_inference() -> None:
    inferred: list[tuple[str, int, str, int]] = []
    checked_candidates: list[str] = []

    class RecordingPolicy:
        def require_allowed(self, candidate: str) -> None:
            checked_candidates.append(candidate)
            if candidate == "203.0.113.9":
                raise NetworkProbeDenied("network_target_disallowed")

    def infer(resolved_ip: str, port: int, family: str, timeout_ms: int) -> str:
        inferred.append((resolved_ip, port, family, timeout_ms))
        return "10.20.0.20"

    result = route_get(
        _route_parameters(),
        policy=RecordingPolicy(),
        resolve_candidates=lambda *_args: (("ipv4", "10.20.0.15"), ("ipv4", "203.0.113.9")),
        infer_source=infer,
        interface_for_source=lambda _ip: "eth0",
        collected_at=NOW,
    )

    assert inferred == [("10.20.0.15", 443, "ipv4", 1000)]
    assert checked_candidates == ["10.20.0.15", "203.0.113.9"]
    assert result.model_dump(mode="json") == {
        "schema_version": "route_get_result_v1",
        "target": "router.example.test",
        "resolved_ip": "10.20.0.15",
        "family": "ipv4",
        "port": 443,
        "source_ip": "10.20.0.20",
        "interface_name": "eth0",
        "strategy": "udp_socket_inference",
        "status": "succeeded",
        "error_code": None,
        "collected_at": "2026-08-28T00:00:00Z",
    }


def test_route_get_denies_when_no_resolved_candidate_is_allowlisted() -> None:
    result = route_get(
        _route_parameters(),
        policy=AgentNetworkProbePolicy.from_values(
            allowed_cidrs=("10.20.0.0/16",), allowed_suffixes=()
        ),
        resolve_candidates=lambda *_args: (("ipv4", "203.0.113.9"),),
        infer_source=lambda *_args: (_ for _ in ()).throw(AssertionError("must not infer")),
        collected_at=NOW,
    )

    assert result.status == "failed"
    assert result.error_code == "network_target_denied"


def test_route_resolution_does_not_truncate_candidates_before_policy_checks(
    monkeypatch,
) -> None:
    records = [
        (socket.AF_INET, socket.SOCK_DGRAM, 17, "", (f"10.20.0.{index}", 443))
        for index in range(1, 18)
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args: records)

    candidates = _resolve_candidates("router.example.test", 443, "ipv4")

    assert candidates == tuple(("ipv4", f"10.20.0.{index}") for index in range(1, 18))


def test_adapter_list_projects_bounded_addresses_without_mac_or_scope() -> None:
    result = adapter_list(
        AdapterListParametersV1(schema_version="adapter_list_parameters_v1"),
        interface_addresses=lambda: {
            "eth0": [
                SimpleNamespace(family=socket.AF_INET, address="10.20.0.20"),
                SimpleNamespace(family=socket.AF_INET6, address="2001:db8::20%eth0"),
                SimpleNamespace(family=17, address="00:11:22:33:44:55"),
            ]
        },
        interface_stats=lambda: {
            "eth0": SimpleNamespace(isup=True, mtu=1500, speed=1000)
        },
        collected_at=NOW,
    )

    assert result.adapter_count == 1
    assert result.up_count == 1
    assert result.adapters[0].model_dump() == {
        "name": "eth0",
        "state": "up",
        "kind": "ethernet",
        "primary": False,
        "ipv4_addresses": ["10.20.0.20"],
        "ipv6_addresses": ["2001:db8::20"],
        "mtu": 1500,
        "speed_mbps": 1000,
    }


def test_service_status_keeps_internal_mapping_and_linux_updater_unsupported() -> None:
    queried_units: list[str] = []
    agent_result = service_status(
        ServiceStatusParametersV1(
            schema_version="service_status_parameters_v1", service_key="endpoint_agent"
        ),
        platform_name="linux",
        linux_service_details=lambda unit: queried_units.append(unit) or (True, "running", "automatic"),
        collected_at=NOW,
    )
    updater_result = service_status(
        ServiceStatusParametersV1(
            schema_version="service_status_parameters_v1",
            service_key="endpoint_agent_updater",
        ),
        platform_name="linux",
        linux_service_details=lambda _unit: (_ for _ in ()).throw(AssertionError("unsupported")),
        collected_at=NOW,
    )

    assert queried_units == ["endpoint-agent.service"]
    assert agent_result.state == "running"
    assert updater_result.status == "failed"
    assert updater_result.error_code == "service_unsupported"
    assert "endpoint-agent.service" not in agent_result.model_dump_json()


def test_service_status_maps_only_fixed_windows_scm_key() -> None:
    queried_services: list[str] = []
    result = service_status(
        ServiceStatusParametersV1(
            schema_version="service_status_parameters_v1",
            service_key="endpoint_agent_updater",
        ),
        platform_name="windows",
        windows_service_details=lambda service: queried_services.append(service)
        or (True, "paused", "manual"),
        collected_at=NOW,
    )

    assert queried_services == ["EndpointAgentUpdater"]
    assert result.model_dump(mode="json") == {
        "schema_version": "service_status_result_v1",
        "service_key": "endpoint_agent_updater",
        "installed": True,
        "state": "paused",
        "start_mode": "manual",
        "status": "succeeded",
        "error_code": None,
        "collected_at": "2026-08-28T00:00:00Z",
    }


def test_linux_service_details_uses_supported_fixed_systemctl_argv(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fixed_systemctl(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            stdout="ActiveState=active\nLoadState=loaded\nUnitFileState=enabled\n"
        )

    monkeypatch.setattr("pc_agent.primitives.read_only.handlers.subprocess.run", fixed_systemctl)

    assert _linux_service_details("endpoint-agent.service") == (True, "running", "automatic")
    assert captured["args"] == (
        (
            "/usr/bin/systemctl",
            "show",
            "endpoint-agent.service",
            "--property=ActiveState,LoadState,UnitFileState",
            "--no-pager",
        ),
    )


def test_windows_missing_fixed_service_returns_safe_not_found_result(monkeypatch) -> None:
    class MissingFixedServiceError(OSError):
        winerror = 1060

    fake_scm = SimpleNamespace(
        QueryServiceStatus=lambda _service: (_ for _ in ()).throw(MissingFixedServiceError())
    )
    monkeypatch.setitem(sys.modules, "win32serviceutil", fake_scm)

    result = service_status(
        ServiceStatusParametersV1(
            schema_version="service_status_parameters_v1", service_key="endpoint_agent"
        ),
        platform_name="windows",
        collected_at=NOW,
    )

    assert result.model_dump(mode="json") == {
        "schema_version": "service_status_result_v1",
        "service_key": "endpoint_agent",
        "installed": False,
        "state": "not_found",
        "start_mode": "unknown",
        "status": "succeeded",
        "error_code": None,
        "collected_at": "2026-08-28T00:00:00Z",
    }


def test_windows_non_missing_scm_failure_remains_bounded_failure(monkeypatch) -> None:
    class ScmAccessDeniedError(OSError):
        winerror = 5

    fake_scm = SimpleNamespace(
        QueryServiceStatus=lambda _service: (_ for _ in ()).throw(ScmAccessDeniedError())
    )
    monkeypatch.setitem(sys.modules, "win32serviceutil", fake_scm)

    result = service_status(
        ServiceStatusParametersV1(
            schema_version="service_status_parameters_v1", service_key="endpoint_agent"
        ),
        platform_name="windows",
        collected_at=NOW,
    )

    assert result.status == "failed"
    assert result.error_code == "service_query_failed"


def test_service_command_rejects_a_raw_service_name() -> None:
    command = AgentCommandV1.model_validate(
        {
            "schema_version": "agent_command_v1",
            "command_id": "00000000-0000-4000-8000-000000000801",
            "device_id": "00000000-0000-4000-8000-000000000802",
            "capability": "system.service_status",
            "parameters": {"service_name": "sshd"},
            "requested_by_service": "endpoint-platform",
            "idempotency_key": "read-only-primitive-801",
            "created_at": "2026-08-28T00:00:00Z",
            "deadline_at": "2026-08-28T00:05:00Z",
        }
    )

    result = execute_read_only_agent_command(
        command,
        policy=AgentNetworkProbePolicy.from_values(allowed_cidrs=(), allowed_suffixes=()),
        completed_at=NOW,
    )

    assert result.status == "failed"
    assert result.message == "read_only_capability_rejected"
