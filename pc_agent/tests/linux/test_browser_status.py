from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from pc_agent.platform.linux.browser_status import LinuxBrowserProbe
from pc_agent.browser_status import build_browser_status_report
from pc_agent.tests.policy.test_runtime import _delivery


def test_policy_and_native_manifest_do_not_fabricate_an_extension_heartbeat(monkeypatch):
    probe = LinuxBrowserProbe(extension_id='a'*32, installed={'chromium'}, process_iter=lambda **_kwargs: [])
    monkeypatch.setattr(probe._policy, 'inspect', lambda _kind: ('ENDPOINT','APPLIED'))
    monkeypatch.setattr(probe, '_native_host_state', lambda _kind: 'READY')
    now = datetime.now(UTC)
    hosts = probe.collect(observed_at=now)
    assert hosts['chrome'].browser_state == 'DETECTED'
    assert hosts['chrome'].running_state == 'CLOSED'
    assert hosts['yandex'].native_host_state == 'UNKNOWN'
    report = build_browser_status_report(_delivery(active=False).policy, hosts, {}, observed_at=now)
    assert report.browsers[0].extension_version is None
    assert report.browsers[0].extension_last_seen_at is None


def test_same_named_foreign_executable_is_not_trusted_as_chromium():
    process = SimpleNamespace(info={'name':'chromium','exe':'/tmp/chromium'})
    probe = LinuxBrowserProbe(extension_id='a'*32, installed={'chromium'},
                              process_iter=lambda **_kwargs:[process])
    facts = probe.collect(observed_at=datetime.now(UTC))
    assert facts['chrome'].running_state == 'UNKNOWN'


def test_native_manifest_is_checked_against_pinned_origin_and_fixed_wrapper(monkeypatch):
    import json
    from pc_agent.platform.linux import browser_status
    identity='a'*32
    manifest={'name':'ru.sosnadmin.endpoint.browser','type':'stdio',
        'path':'/usr/lib/endpoint-agent/browser-bridge','allowed_origins':[f'chrome-extension://{identity}/']}
    def read(path):
        return json.dumps(manifest).encode() if path.suffix == '.json' else b'root owned wrapper'
    monkeypatch.setattr(browser_status, '_read', read)
    monkeypatch.setattr(browser_status.os, 'access', lambda *_args: True)
    probe = LinuxBrowserProbe(extension_id=identity, installed={'chromium'})
    assert probe._native_host_state('chromium') == 'READY'
    assert probe._native_host_state('yandex') == 'READY'
    manifest['path']='/tmp/foreign-native-host'
    assert probe._native_host_state('chromium') == 'MISSING'


def test_installed_yandex_is_reported_separately_with_real_policy_and_native_facts(monkeypatch):
    probe = LinuxBrowserProbe(extension_id='a'*32, installed={'yandex'}, process_iter=lambda **_kwargs: [])
    monkeypatch.setattr(probe._policy, 'inspect', lambda kind: ('EXTERNAL','APPLIED') if kind=='yandex' else ('NONE','NOT_APPLIED'))
    monkeypatch.setattr(probe, '_native_host_state', lambda kind: 'READY' if kind=='yandex' else 'MISSING')
    facts = probe.collect(observed_at=datetime.now(UTC))
    assert facts['yandex'].browser_state == 'DETECTED'
    assert facts['yandex'].running_state == 'CLOSED'
    assert facts['yandex'].policy_owner == 'EXTERNAL'
    assert facts['yandex'].native_host_state == 'READY'
    assert facts['chrome'].browser_state == 'UNKNOWN'
    assert probe.bridge_available()


def test_yandex_running_requires_its_trusted_real_binary(monkeypatch):
    from pc_agent.platform.linux import browser_status
    process = SimpleNamespace(info={'name':'yandex_browser','exe':'/usr/lib64/yandex/browser/yandex_browser'})
    monkeypatch.setattr(browser_status, '_trusted_executable', lambda path: path.startswith('/usr/lib64/yandex/'))
    probe = LinuxBrowserProbe(extension_id='a'*32, installed={'yandex'}, process_iter=lambda **_kwargs:[process])
    assert probe.collect(observed_at=datetime.now(UTC))['yandex'].running_state == 'RUNNING'
    process.info['exe'] = '/tmp/yandex_browser'
    assert probe.collect(observed_at=datetime.now(UTC))['yandex'].running_state == 'UNKNOWN'


def test_yandex_detection_does_not_depend_on_an_unversioned_launcher(monkeypatch):
    monkeypatch.setattr(Path, 'is_file', lambda path: path.as_posix()=='/usr/lib64/yandex/browser/yandex_browser')
    probe = LinuxBrowserProbe(extension_id='a'*32, process_iter=lambda **_kwargs: [])
    assert probe._products == {'yandex'}
    assert probe.collect(observed_at=datetime.now(UTC))['yandex'].browser_state == 'DETECTED'
