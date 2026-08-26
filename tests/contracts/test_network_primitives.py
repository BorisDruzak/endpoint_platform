from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

import endpoint_contracts as contracts
from endpoint_contracts.network_primitives import (
    DnsResolveParametersV1,
    DnsResolveResultV1,
    NetworkPingParametersV1,
    NetworkPingResultV1,
    TcpConnectParametersV1,
    TcpConnectResultV1,
)


def test_network_primitive_contracts_are_publicly_exported() -> None:
    assert contracts.DnsResolveParametersV1 is DnsResolveParametersV1
    assert contracts.NetworkPingParametersV1 is NetworkPingParametersV1
    assert contracts.TcpConnectParametersV1 is TcpConnectParametersV1


def test_dns_resolve_contract_accepts_bounded_safe_result() -> None:
    result = DnsResolveResultV1(
        schema_version="dns_resolve_result_v1",
        target="example.test",
        canonical_name="example.test",
        addresses=[{"family": "ipv4", "address": "192.0.2.10"}],
        address_count=1,
        status="succeeded",
        error_code=None,
        collected_at=datetime.now(UTC),
    )

    assert result.address_count == 1
    assert result.addresses[0].family == "ipv4"


@pytest.mark.parametrize(
    "target",
    ["https://example.test", "example.test/path", "user@example.test", "bad\x00host"],
)
def test_dns_resolve_parameters_reject_non_target_syntax(target: str) -> None:
    with pytest.raises(ValidationError):
        DnsResolveParametersV1(
            schema_version="dns_resolve_parameters_v1", target=target, family="any"
        )


def test_network_ping_contract_enforces_bounds_and_hides_raw_output() -> None:
    valid = NetworkPingParametersV1(
        schema_version="network_ping_parameters_v1",
        target="198.51.100.8",
        count=5,
        timeout_ms=5000,
    )

    assert valid.count == 5
    with pytest.raises(ValidationError):
        NetworkPingParametersV1(
            schema_version="network_ping_parameters_v1",
            target="198.51.100.8",
            count=6,
            timeout_ms=5000,
        )
    with pytest.raises(ValidationError):
        NetworkPingResultV1(
            schema_version="network_ping_result_v1",
            target="198.51.100.8",
            resolved_ip="198.51.100.8",
            transmitted=1,
            received=1,
            packet_loss_percent=0,
            min_ms=1.0,
            avg_ms=1.0,
            max_ms=1.0,
            reachable=True,
            status="succeeded",
            error_code=None,
            collected_at=datetime.now(UTC),
            stdout="forbidden",
        )


def test_tcp_connect_contract_enforces_port_timeout_and_safe_result() -> None:
    parameters = TcpConnectParametersV1(
        schema_version="tcp_connect_parameters_v1",
        target="example.test",
        port=443,
        timeout_ms=3000,
    )
    result = TcpConnectResultV1(
        schema_version="tcp_connect_result_v1",
        target="example.test",
        resolved_ip="192.0.2.20",
        port=443,
        reachable=True,
        latency_ms=2.5,
        status="succeeded",
        error_code=None,
        collected_at=datetime.now(UTC),
    )

    assert parameters.port == result.port == 443
    with pytest.raises(ValidationError):
        TcpConnectParametersV1(
            schema_version="tcp_connect_parameters_v1",
            target="example.test",
            port=0,
            timeout_ms=99,
        )
