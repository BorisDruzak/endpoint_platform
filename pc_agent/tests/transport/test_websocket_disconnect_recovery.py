"""Transient EOF must reconnect; authenticated rejection and policy closes stay closed."""
from pathlib import Path
from types import SimpleNamespace

import aiohttp
from aiohttp import web
import pytest

from pc_agent.transport.base import GatewayCredentialRejected, GatewayTerminalError
from pc_agent.transport.websocket import GatewayTransportUnavailable, WebSocketGatewayTransport


class _ClosingSocket:
    def __init__(self, kind, data, close_code=None, error=None):
        self.frame = SimpleNamespace(type=kind, data=data)
        self.close_code = close_code
        self._error = error

    async def receive(self):
        return self.frame

    def exception(self):
        return self._error


def _transport(socket):
    transport = WebSocketGatewayTransport(
        ca_file=Path('unused-test-ca.pem'), credential='fixture-only',
        endpoint_origin='https://example.invalid',
    )
    transport._socket = socket
    return transport


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,data,close_code', [
    (aiohttp.WSMsgType.CLOSE, 1006, 1006),
    (aiohttp.WSMsgType.CLOSED, None, 1006),
    (aiohttp.WSMsgType.CLOSED, None, None),
    (aiohttp.WSMsgType.CLOSING, None, None),
])
async def test_abnormal_or_eof_close_is_retryable(kind, data, close_code):
    with pytest.raises(GatewayTransportUnavailable):
        await _transport(_ClosingSocket(kind, data, close_code)).receive()


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,data,close_code', [
    (aiohttp.WSMsgType.CLOSE, 1008, 1008),
    (aiohttp.WSMsgType.CLOSED, None, 1008),
    (aiohttp.WSMsgType.CLOSE, 4499, 4499),
])
async def test_policy_or_unknown_close_remains_terminal(kind, data, close_code):
    with pytest.raises(GatewayTerminalError) as error:
        await _transport(_ClosingSocket(kind, data, close_code)).receive()
    assert not isinstance(error.value, GatewayTransportUnavailable)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,data,close_code', [
    (aiohttp.WSMsgType.CLOSE, 4401, 4401),
    (aiohttp.WSMsgType.CLOSED, None, 4403),
])
async def test_credential_close_remains_rejected(kind, data, close_code):
    with pytest.raises(GatewayCredentialRejected):
        await _transport(_ClosingSocket(kind, data, close_code)).receive()


@pytest.mark.asyncio
async def test_tls_failure_behind_abnormal_close_remains_terminal():
    import ssl

    socket = _ClosingSocket(aiohttp.WSMsgType.CLOSED, None, 1006, ssl.SSLError('fixture'))
    with pytest.raises(GatewayTerminalError) as error:
        await _transport(socket).receive()
    assert not isinstance(error.value, GatewayTransportUnavailable)


@pytest.mark.asyncio
async def test_real_tcp_abort_is_retryable_with_aiohttp():
    async def abort_after_upgrade(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        request.transport.abort()
        return ws

    app = web.Application()
    app.router.add_get('/ws', abort_after_upgrade)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(f'http://127.0.0.1:{port}/ws') as socket:
                with pytest.raises(GatewayTransportUnavailable):
                    await _transport(socket).receive()
    finally:
        await runner.cleanup()
