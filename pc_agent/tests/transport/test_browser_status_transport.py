"""Browser status uses the existing sequenced Gateway WSS transport."""

from __future__ import annotations

import pytest

from endpoint_contracts.browser_status import BrowserStatusReportV1
from pc_agent.transport.websocket import WebSocketGatewayTransport
from tests.contracts.test_browser_status_v1 import _report


@pytest.mark.asyncio
async def test_status_report_sends_typed_sequenced_wss_frame(tmp_path) -> None:
    frames = []

    class Socket:
        async def send_json(self, frame):
            frames.append(frame)

    transport = WebSocketGatewayTransport(
        ca_file=tmp_path / "ca.pem", credential="test-only-token",
        endpoint_origin="https://endpoint.sosnadmin.local",
    )
    transport._socket = Socket()
    report = BrowserStatusReportV1.model_validate(_report())
    await transport.send_browser_status_report(report)
    assert frames[0]["kind"] == "browser_status_report"
    assert frames[0]["sequence"] == 1
    assert frames[0]["payload"]["browsers"][0]["browser_family"] == "chrome"
