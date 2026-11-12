from datetime import UTC, datetime, timedelta
import json
from socketserver import BaseRequestHandler, TCPServer
from threading import Thread
from types import SimpleNamespace
from uuid import uuid4

import pytest

from endpoint_contracts import AgentCommandV1
from pc_agent.context_profiles.health import collect_health
from pc_agent.context_profiles import probe as probe_module
from pc_agent.context_profiles.probe import SystemProbe
from pc_agent.context_profiles.server_health import collect_server_health
from pc_agent.runtime.command_executor import CommandExecutor
from pc_agent.runtime.main import main


class Probe:
    platform_name = "linux"

    def read_text(self, path, max_bytes):
        return {
            "/proc/uptime": "25.0 10.0",
            "/proc/loadavg": "0.5 0.5 0.5",
            "/proc/meminfo": "MemAvailable: 4096 kB",
        }[path]

    def run(self, command, timeout_seconds, max_bytes):
        return "active"


def test_unassigned_agent_preserves_existing_health_payload(monkeypatch):
    monkeypatch.delenv("ENDPOINT_AGENT_SERVER_ROLE", raising=False)
    sections = collect_health(Probe()).model_dump(mode="json")["sections"]
    assert set(sections) == {"resources", "services"}
    assert main(["--print-server-health"]) == 2


async def test_endpoint_platform_health_command_reports_worker_and_low_space(monkeypatch):
    monkeypatch.setenv("ENDPOINT_AGENT_SERVER_ROLE", "endpoint_platform")
    probe = Probe()
    probe.server_service_state = lambda unit: (
        "active/exited" if unit == "endpoint-platform-worker.service" else "active/running"
    )
    probe.server_local_mounts = lambda: {"/", "/boot"}
    probe.server_disk_usage = lambda mount: SimpleNamespace(
        total=50 * 1024**3, free=400 * 1024**2 if mount == "/" else 2 * 1024**3,
        percent=99 if mount == "/" else 15,
    )
    probe.server_http_status = lambda port, path: 200

    executor = CommandExecutor(probe_factory=lambda: probe)
    await executor.start()
    now = datetime.now(UTC)
    try:
        result = await executor.execute(AgentCommandV1(
            schema_version="agent_command_v1", command_id=uuid4(), device_id=uuid4(),
            capability="context.health.collect", requested_by_service="scheduler",
            idempotency_key="server-health", created_at=now, deadline_at=now + timedelta(minutes=1),
        ))
    finally:
        await executor.stop()
    assert result.status == "succeeded"
    section = result.result_items[0]["sections"]["server"]

    assert section["role"] == "endpoint_platform"
    assert {item["name"]: item["status"] for item in section["services"]}[
        "endpoint-platform-worker.service"
    ] == "failed"
    assert {item["mount"]: item["status"] for item in section["volumes"]} == {
        "/": "critical", "/boot": "ok",
    }
    assert section["applications"][0]["status"] == "ok"


def test_openvpn_distinguishes_web_response_listener_and_missing_mount(monkeypatch):
    monkeypatch.setenv("ENDPOINT_AGENT_SERVER_ROLE", "openvpn")
    probe = Probe()
    probe.server_service_state = lambda unit: "active/running"
    probe.server_local_mounts = lambda: {"/", "/boot"}
    probe.server_disk_usage = lambda mount: SimpleNamespace(
        total=20 * 1024**3, free=5 * 1024**3, percent=75,
    )
    probe.server_http_status = lambda port, path: 303
    probe.server_udp_listener = lambda port: False

    section = collect_server_health(probe)

    assert {item.mount: item.status for item in section.volumes}["/var/lib/netctl"] == "missing"
    assert {item.name: item.status for item in section.applications} == {
        "openvpn_web_http": "ok", "openvpn_udp_listener": "failed",
    }
    probe.server_http_status = lambda port, path: 700
    assert collect_server_health(probe).applications[0].status == "unknown"


def test_local_http_uses_total_deadline_while_response_is_incomplete(monkeypatch):
    monkeypatch.setattr(probe_module, "_HTTP_PROBE_TIMEOUT", 0.25)

    class IncompleteResponse(BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            self.request.recv(1024)
            self.request.sendall(b"HTTP/1.1 200 OK\r\n")
            self.request.recv(1024)

    with TCPServer(("127.0.0.1", 0), IncompleteResponse) as server:
        thread = Thread(target=server.handle_request, daemon=True)
        thread.start()
        with pytest.raises(TimeoutError):
            SystemProbe().server_http_status(server.server_address[1], "/")
        thread.join(timeout=2)


@pytest.mark.parametrize("role", ["directum", "ad_directum"])
def test_directum_uses_verified_service_and_http_and_reports_missing_broker(monkeypatch, role):
    monkeypatch.setenv("ENDPOINT_AGENT_SERVER_ROLE", role)
    probe = Probe()
    probe.platform_name = "windows"
    probe.server_service_state = lambda service: "missing" if service == "RabbitMQ" else "running"
    probe.server_local_mounts = lambda: {"C:\\", "S:\\"}
    probe.server_disk_usage = lambda mount: SimpleNamespace(
        total=100 * 1024**3, free=40 * 1024**3, percent=60,
    )
    probe.server_tcp_listener = lambda port: port != 5672
    probe.server_http_status = lambda port, path: 302

    section = collect_server_health(probe)
    assert {item.mount for item in section.volumes} == {"C:\\", "S:\\"}
    services = {
        "DirectumRXServiceRunner": "ok", "W3SVC": "ok", "RabbitMQ": "missing",
    }
    applications = {
        "directum_http": "ok", "directum_rabbitmq_tcp": "failed",
    }
    if role == "ad_directum":
        services.update(dict.fromkeys(("NTDS", "DNS", "Kdc", "Netlogon", "ADWS"), "ok"))
        applications.update({"ad_dns_tcp": "ok", "ad_kerberos_tcp": "ok", "ad_ldap_tcp": "ok"})
    assert {item.name: item.status for item in section.services} == services
    assert {item.name: item.status for item in section.applications} == applications


def test_ad_and_consultant_checks_are_independent(monkeypatch):
    monkeypatch.setenv("ENDPOINT_AGENT_SERVER_ROLE", "ad_consultant")
    probe = Probe()
    probe.platform_name = "windows"
    probe.server_service_state = lambda service: "running"
    probe.server_local_mounts = set
    probe.server_tcp_listener = lambda port: port != 389

    def check_web(port, path):
        assert (port, path) == (80, "/cons/")
        raise TimeoutError

    probe.server_http_status = check_web
    section = collect_server_health(probe)
    assert {"NTDS", "DNS", "ConsServiceS400.2.24"} <= {item.name for item in section.services}
    assert {item.name: item.status for item in section.applications} == {
        "ad_dns_tcp": "ok", "ad_kerberos_tcp": "ok", "ad_ldap_tcp": "failed",
        "consultant_http": "unknown", "consultant_tcp": "ok",
    }


def test_proxmox_profile_reports_cluster_and_storage_failures(monkeypatch):
    monkeypatch.setenv("ENDPOINT_AGENT_SERVER_ROLE", "proxmox")
    probe = Probe()
    probe.server_service_state = lambda unit: "inactive/dead" if unit == "pvestatd.service" else "active/running"
    probe.server_local_mounts = lambda: {"/"}
    probe.server_disk_usage = lambda mount: SimpleNamespace(total=50 * 1024**3, free=20 * 1024**3, percent=60)
    probe.proxmox_health_snapshot = lambda: {
        "checks": {"proxmox_api": "ok", "proxmox_quorum": "ok", "proxmox_members": "failed"},
        "http_status": 401,
        "storage": [
            {"id": "local-lvm", "available": True, "total": 100 * 1024**3, "used": 93 * 1024**3},
            {"id": "main-zfs", "available": False},
        ],
    }
    health = collect_server_health(probe)
    assert health.role == "proxmox"
    assert {item.name: item.status for item in health.services}["pvestatd.service"] == "failed"
    assert {item.mount: item.status for item in health.volumes} == {
        "/": "ok", "PVE / local-lvm": "critical", "PVE / main-zfs": "critical",
    }
    assert {item.name: item.status for item in health.applications} == {
        "proxmox_api": "ok", "proxmox_quorum": "ok", "proxmox_members": "failed", "proxmox_storage": "unknown",
    }
    assert health.applications[0].http_status == 401


def test_proxmox_missing_snapshot_is_unknown(monkeypatch):
    monkeypatch.setenv("ENDPOINT_AGENT_SERVER_ROLE", "proxmox")
    probe = Probe()
    probe.server_service_state = lambda unit: "active/running"
    probe.server_local_mounts = set
    def missing():
        raise FileNotFoundError
    probe.proxmox_health_snapshot = missing
    health = collect_server_health(probe)
    assert all(item.status == "unknown" for item in health.applications)


def test_proxmox_snapshot_expires_instead_of_reusing_old_state(monkeypatch, tmp_path):
    snapshot = tmp_path / "status.json"
    monkeypatch.setattr(probe_module, "Path", lambda _: snapshot)
    monkeypatch.setattr(probe_module.time, "time", lambda: 10_000)
    snapshot.write_text(json.dumps({"schema_version": 1, "sampled_at": 9_999}), encoding="utf-8")
    assert SystemProbe().proxmox_health_snapshot()["sampled_at"] == 9_999
    snapshot.write_text(json.dumps({"schema_version": 1, "sampled_at": 9_819}), encoding="utf-8")
    with pytest.raises(ValueError, match="stale"):
        SystemProbe().proxmox_health_snapshot()


@pytest.mark.parametrize("role", ["unknown", "directum"])
def test_incompatible_configuration_does_not_run_probes(monkeypatch, role):
    monkeypatch.setenv("ENDPOINT_AGENT_SERVER_ROLE", role)
    warnings = []
    assert collect_server_health(Probe(), warnings=warnings) is None
    assert warnings == ["unsupported_platform" if role == "directum" else "source_unavailable"]
