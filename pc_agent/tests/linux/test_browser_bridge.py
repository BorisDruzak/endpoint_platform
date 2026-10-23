"""Linux uses the existing Chromium protocol over mutually authenticated IPC."""
from datetime import UTC, datetime
from io import BytesIO
import json
import struct

import pytest

from pc_agent.browser_protocol import BrowserBridgeAckV1
from pc_agent.local_sensor_protocol import LocalBrowserEnvelopeV1
from pc_agent.platform.linux import browser_bridge

EXTENSION_ID = 'a' * 32
ORIGIN = f'chrome-extension://{EXTENSION_ID}/'


def frame(**extra):
    data = dict(schema_version='browser_sensor_hello_v1', protocol_version=1,
                extension_id=EXTENSION_ID, extension_version='0.1.0',
                browser_family='chrome', observed_at=datetime.now(UTC).isoformat())
    body = json.dumps(data | extra).encode()
    return struct.pack('<I', len(body)) + body


def test_linux_bridge_forwards_only_the_common_typed_envelope(monkeypatch):
    sent = []
    monkeypatch.setattr(browser_bridge, 'exchange', lambda data: sent.append(json.loads(data)) or
                        b'{"schema_version":"browser_bridge_ack_v1","accepted":true,"error_code":"OK"}')
    output = BytesIO()
    browser_bridge.run_native_bridge(stdin=BytesIO(frame()), stdout=output,
        arguments=[ORIGIN], expected_extension_id=EXTENSION_ID)
    assert sent[0]['source'] == 'browser'
    assert sent[0]['extension_id'] == EXTENSION_ID
    assert BrowserBridgeAckV1.model_validate_json(output.getvalue()[4:]).accepted


@pytest.mark.parametrize('arguments', [[], ['https://example.test/'], [ORIGIN, '--unexpected']])
def test_linux_bridge_rejects_origin_before_reading_stdin(arguments):
    class Unreadable:
        def read(self, count):
            pytest.fail('unapproved native invocation read a message')
    with pytest.raises(browser_bridge.BrowserBridgeInvocationError):
        browser_bridge.run_native_bridge(stdin=Unreadable(), stdout=BytesIO(),
            arguments=arguments, expected_extension_id=EXTENSION_ID)


def test_linux_bridge_does_not_echo_content_or_report_ipc_failure_as_delivery(monkeypatch):
    monkeypatch.setattr(browser_bridge, 'exchange', lambda _data: (_ for _ in ()).throw(OSError('PRIVATE_MARKER')))
    output = BytesIO()
    browser_bridge.run_native_bridge(stdin=BytesIO(frame()), stdout=output,
        arguments=[ORIGIN], expected_extension_id=EXTENSION_ID)
    reply = BrowserBridgeAckV1.model_validate_json(output.getvalue()[4:])
    assert not reply.accepted and reply.error_code == 'IPC_UNAVAILABLE'
    assert b'PRIVATE_MARKER' not in output.getvalue()
    envelope = LocalBrowserEnvelopeV1.model_validate(dict(
        schema_version='local_sensor_envelope_v1', source='browser',
        extension_id=EXTENSION_ID, message=json.loads(frame()[4:]),
    ))
    monkeypatch.setattr(browser_bridge, 'exchange', lambda _data: b'{"schema_version":"browser_bridge_ack_v1","accepted":true,"error_code":"OK","content":"PRIVATE_MARKER"}')
    with pytest.raises(ValueError):
        browser_bridge.forward_to_agent(envelope)


def test_linux_native_entry_never_runs_as_root_or_reads_credentials(monkeypatch):
    from pc_agent.platform.linux import browser_bridge_entry as entry
    monkeypatch.setattr(entry.os, 'getuid', lambda: 0, raising=False)
    monkeypatch.setattr(entry, 'run_native_bridge', lambda **_kwargs: pytest.fail('root native host ran'))
    assert entry.main([ORIGIN]) == 1


def test_linux_native_entry_uses_packaged_identity_and_binary_stdio(monkeypatch):
    from types import SimpleNamespace
    from pc_agent.platform.linux import browser_bridge_entry as entry
    monkeypatch.setattr(entry.os, 'getuid', lambda: 1000, raising=False)
    monkeypatch.setattr(entry.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(entry, 'load_packaged_extension_id', lambda: EXTENSION_ID)
    seen = []
    monkeypatch.setattr(entry, 'run_native_bridge', lambda **kwargs: seen.append(kwargs))
    source, output = BytesIO(), BytesIO()
    monkeypatch.setattr(entry.sys, 'stdin', SimpleNamespace(buffer=source))
    monkeypatch.setattr(entry.sys, 'stdout', SimpleNamespace(buffer=output))
    assert entry.main([ORIGIN]) == 0
    assert seen == [dict(stdin=source, stdout=output, arguments=[ORIGIN], expected_extension_id=EXTENSION_ID)]


def test_native_identity_is_the_public_id_in_the_frozen_package(monkeypatch, tmp_path):
    from pc_agent import browser_identity
    asset = tmp_path / 'browser_sensor/extension-id.txt'
    asset.parent.mkdir()
    asset.write_text(EXTENSION_ID, encoding='ascii')
    monkeypatch.setattr(browser_identity.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(browser_identity.sys, '_MEIPASS', str(tmp_path), raising=False)
    assert browser_identity.load_packaged_extension_id() == EXTENSION_ID
    asset.write_text('invalid', encoding='ascii')
    with pytest.raises(ValueError):
        browser_identity.load_packaged_extension_id()
