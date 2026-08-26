from datetime import UTC, datetime
import socket

from endpoint_contracts.network_primitives import (
    DnsResolveParametersV1,
    NetworkPingParametersV1,
    TcpConnectParametersV1,
)
from endpoint_contracts import AgentCommandV1
from pc_agent.primitives.network.command_execution import execute_network_agent_command
from pc_agent.primitives.network.policy import AgentNetworkProbePolicy
from pc_agent.primitives.network.handlers import (
    ping_host,
    resolve_dns,
    tcp_connect,
)


def test_dns_handler_normalizes_addresses_without_resolver_text() -> None:
    parameters = DnsResolveParametersV1(
        schema_version="dns_resolve_parameters_v1", target="api.example.test", family="any"
    )

    result = resolve_dns(
        parameters,
        getaddrinfo=lambda *_args: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "api.example.test", ("192.0.2.2", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "api.example.test", ("2001:db8::2", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "api.example.test", ("192.0.2.2", 0)),
        ],
        getfqdn=lambda _target: "api.example.test",
        collected_at=datetime(2026, 8, 26, tzinfo=UTC),
    )

    assert result.status == "succeeded"
    assert result.address_count == 2
    assert "stdout" not in result.model_dump()


def test_dns_handler_maps_resolver_failure_to_stable_code() -> None:
    parameters = DnsResolveParametersV1(
        schema_version="dns_resolve_parameters_v1", target="missing.example.test", family="ipv4"
    )

    result = resolve_dns(
        parameters,
        getaddrinfo=lambda *_args: (_ for _ in ()).throw(socket.gaierror()),
        getfqdn=lambda target: target,
        collected_at=datetime(2026, 8, 26, tzinfo=UTC),
    )

    assert result.status == "failed"
    assert result.error_code == "dns_not_found"
    assert result.addresses == []


def test_tcp_handler_returns_bounded_success_without_socket_exception() -> None:
    parameters = TcpConnectParametersV1(
        schema_version="tcp_connect_parameters_v1",
        target="api.example.test",
        port=443,
        timeout_ms=3000,
    )

    class Connection:
        def close(self) -> None:
            return None

    result = tcp_connect(
        parameters,
        resolve=lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.4", 443))],
        connect=lambda *_args, **_kwargs: Connection(),
        monotonic_values=iter((10.0, 10.025)),
        collected_at=datetime(2026, 8, 26, tzinfo=UTC),
    )

    assert result.status == "succeeded"
    assert result.reachable is True
    assert result.latency_ms == 25.0
    assert "exception" not in result.model_dump()


def test_ping_handler_normalizes_fixed_adapter_output_without_raw_stdout() -> None:
    parameters = NetworkPingParametersV1(
        schema_version="network_ping_parameters_v1",
        target="10.20.1.10",
        count=4,
        timeout_ms=1000,
    )

    result = ping_host(
        parameters,
        platform_name="linux",
        runner=lambda _argv, _timeout: (
            0,
            "4 packets transmitted, 3 received, 25% packet loss\n"
            "rtt min/avg/max/mdev = 1.000/2.000/3.000/0.500 ms\n",
        ),
        resolve=lambda *_args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.1.10", 0))],
        collected_at=datetime(2026, 8, 26, tzinfo=UTC),
    )

    assert result.status == "succeeded"
    assert result.transmitted == 4
    assert result.received == 3
    assert result.packet_loss_percent == 25.0
    assert result.avg_ms == 2.0
    assert "stdout" not in result.model_dump()


def test_ping_handler_uses_fixed_windows_adapter_without_raw_output() -> None:
    parameters = NetworkPingParametersV1(
        schema_version="network_ping_parameters_v1",
        target="10.20.1.10",
        count=2,
        timeout_ms=1500,
    )
    observed_argv: list[tuple[str, ...]] = []

    def runner(argv: tuple[str, ...], _timeout: float) -> tuple[int, str]:
        observed_argv.append(argv)
        return (
            0,
            "Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
            "Minimum = 1ms, Maximum = 3ms, Average = 2ms\n",
        )

    result = ping_host(
        parameters,
        platform_name="windows",
        runner=runner,
        resolve=lambda *_args: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.1.10", 0))
        ],
        collected_at=datetime(2026, 8, 26, tzinfo=UTC),
    )

    assert observed_argv == [("ping", "-n", "2", "-w", "1500", "10.20.1.10")]
    assert result.status == "succeeded"
    assert (result.min_ms, result.avg_ms, result.max_ms) == (1.0, 2.0, 3.0)
    assert "Packets:" not in str(result.model_dump())


def test_ping_handler_parses_localized_windows_summary() -> None:
    parameters = NetworkPingParametersV1(
        schema_version="network_ping_parameters_v1",
        target="192.168.101.118",
        count=1,
        timeout_ms=1000,
    )

    result = ping_host(
        parameters,
        platform_name="windows",
        runner=lambda _argv, _timeout: (
            0,
            "Пакетов: отправлено = 1, получено = 1, потеряно = 0\n"
            "Минимальное = 0мсек, Максимальное = 0 мсек, Среднее = 0 мсек\n",
        ),
        resolve=lambda *_args: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.101.118", 0))
        ],
        collected_at=datetime(2026, 8, 26, tzinfo=UTC),
    )

    assert result.status == "succeeded"
    assert result.reachable is True
    assert (result.min_ms, result.avg_ms, result.max_ms) == (0.0, 0.0, 0.0)


def test_network_command_execution_applies_policy_before_invoking_handler() -> None:
    command = AgentCommandV1.model_validate(
        {
            "schema_version": "agent_command_v1",
            "command_id": "00000000-0000-4000-8000-000000000501",
            "device_id": "00000000-0000-4000-8000-000000000502",
            "capability": "dns.resolve",
            "parameters": {"target": "127.0.0.1", "family": "any"},
            "requested_by_service": "test-runtime",
            "idempotency_key": "network-command-test-501",
            "created_at": "2026-08-26T00:00:00Z",
            "deadline_at": "2026-08-26T00:05:00Z",
        }
    )
    calls: list[str] = []

    result = execute_network_agent_command(
        command,
        policy=AgentNetworkProbePolicy.from_values(
            allowed_cidrs=("0.0.0.0/0",), allowed_suffixes=()
        ),
        dns_handler=lambda _parameters: calls.append("dns"),
    )

    assert result.status == "failed"
    assert result.message == "network_target_forbidden_address"
    assert calls == []
