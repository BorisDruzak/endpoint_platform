from datetime import UTC, datetime
import socket

from endpoint_contracts.network_primitives import (
    DnsResolveParametersV1,
    NetworkPingParametersV1,
    TcpConnectParametersV1,
)
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
