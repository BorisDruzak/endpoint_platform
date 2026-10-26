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


def test_wss_hello_advertises_power_within_negotiated_feature_bound(monkeypatch, tmp_path):
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
    assert "endpoint.policy-readiness.v1" in hello.protocol_features
    assert len(hello.protocol_features) <= 9
    # Hello's compatibility http-pull boot ID must not become native evidence.
    assert not hello.boot_id or hello.boot_id == "http-pull"

@pytest.mark.parametrize("maximum_identifiers", [False, True])
async def test_near_limit_spool_batches_drain_through_real_wire_parser(tmp_path, maximum_identifiers):
    from datetime import timedelta
    import aiohttp
    from endpoint_contracts.power_events import MAX_POWER_EVENT_BATCH_BYTES_V1
    from endpoint_server.gateway.protocol import parse_agent_envelope
    from pc_agent.power.native import native_event
    from .test_spool import ack

    class WireSocket:
        # Exercise aiohttp's production default JSON serializer and send boundary.
        send_json = aiohttp.ClientWebSocketResponse.send_json

        async def send_str(self, data, compress=None):
            self.raw = data
            self.parsed = parse_agent_envelope(data, maximum_message_bytes=1048576)

    spool = PowerEventSpool(tmp_path)
    await spool.open()
    observed = NOW + timedelta(microseconds=123456)
    events = [native_event(
        source=("s" * 128 if maximum_identifiers else "windows.notification"), boot_id="b" * (128 if maximum_identifiers else 64),
        native_record_id=str(i).zfill(128 if maximum_identifiers else 64),
        event_kind="OS_SLEEP_STARTED", sleep_subtype="unknown",
        occurred_at=observed, observed_at=observed,
    ) for i in range(128)]
    await spool.commit_page(page(events), now=observed)
    transport = WebSocketGatewayTransport(ca_file=Path("ca"), credential="a" * 43)
    socket = WireSocket()
    transport._socket = socket
    transport._maximum_message_bytes = 1048576
    transport._outgoing_sequence = 2**63 - 3
    transport._protocol_features = frozenset({"endpoint.power-events.v1"})
    delivered = []
    sizes = []
    while (await spool.stats()).queued_events:
        batch = await spool.next_batch(now=observed)
        assert batch.events
        await transport.send_power_event_batch(batch)
        sizes.append(len(socket.raw.encode("utf-8")))
        delivered.extend(e.event_identifier for e in socket.parsed.payload.events)
        assert await spool.acknowledge(batch, ack(batch))
    assert len(sizes) == 2
    assert 59000 < sizes[0] <= MAX_POWER_EVENT_BATCH_BYTES_V1
    assert delivered == [e.event_identifier for e in events]
