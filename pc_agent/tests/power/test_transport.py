from pathlib import Path
from uuid import uuid4

import pytest

from pc_agent.power.spool import PowerEventSpool
from pc_agent.runtime import application
from pc_agent.tests.transport.test_websocket_transport import (
    _gateway_hello_body,
    _HandshakeSocket,
)
from pc_agent.transport.base import GatewayProtocolIncompatible
from pc_agent.transport.websocket import WebSocketGatewayTransport

from .test_spool import NOW, event, page


async def test_power_frames_require_negotiation_and_canonical_envelope(tmp_path):
    spool = PowerEventSpool(tmp_path)
    await spool.open()
    await spool.commit_page(page([event()]), now=NOW)
    batch = await spool.next_batch(now=NOW)
    transport = WebSocketGatewayTransport(ca_file=Path("ca"), credential="a" * 43)
    socket = _HandshakeSocket(_gateway_hello_body())
    transport._socket = socket
    with pytest.raises(GatewayProtocolIncompatible):
        await transport.send_power_event_batch(batch)
    assert not socket.sent
    transport._protocol_features = frozenset({"endpoint.power-events.v1"})
    assert await transport.send_power_event_batch(batch) == 1
    assert socket.sent[0]["kind"] == "power_event_batch"
    assert socket.sent[0]["payload"] == batch.model_dump(mode="json")


def test_wss_hello_advertises_power_within_eight_feature_bound(monkeypatch, tmp_path):
    from pc_agent.runtime.application import RuntimeSettings

    monkeypatch.setattr(application, "read_enrollment_device_id", lambda _path: uuid4())
    hello = application._load_hello(
        RuntimeSettings(
            data_root=tmp_path,
            install_root=tmp_path,
            ca_file=tmp_path / "ca",
            endpoint_origin="https://endpoint.sosnadmin.local",
            transport_mode="gateway_wss",
        )
    )
    assert "endpoint.power-events.v1" in hello.protocol_features
    assert len(hello.protocol_features) <= 8
    # Hello's compatibility http-pull boot ID must not become native evidence.
    assert not hello.boot_id or hello.boot_id == "http-pull"
