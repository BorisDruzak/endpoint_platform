"""Root helper owns one file and never takes over existing corporate policy."""
import json
import os
from pathlib import Path

import pytest

from pc_agent.platform.linux.browser_policy import LinuxBrowserPolicy, BrowserPolicyConflict, OWNED_POLICY_NAME

pytestmark = pytest.mark.skipif(os.name != 'posix' or getattr(os, 'geteuid', lambda: -1)() != 0,
    reason='native root-owned filesystem boundary; run in the authorized ALT root fixture')
EXTENSION = 'a' * 32


@pytest.fixture
def store(tmp_path):
    managed, state = tmp_path / 'managed', tmp_path / 'state'
    managed.mkdir(mode=0o755); state.mkdir(mode=0o755)
    return LinuxBrowserPolicy(extension_id=EXTENSION, roots={'chromium':managed},
                              state_root=state, installed={'chromium'})


def test_apply_and_relinquish_touch_only_owned_file(store):
    managed = store.roots['chromium']
    other = managed / 'corporate.json'
    original = b'{"HomepageLocation":"https://example.test/","ExtensionInstallForcelist":[]}'
    other.write_bytes(original)
    assert store.apply('chrome') == 'APPLIED'
    assert store.inspect('chromium') == ('ENDPOINT', 'APPLIED')
    assert other.read_bytes() == original
    assert store.apply('chrome') == 'APPLIED'
    assert store.relinquish('chrome') == 'EXTERNALLY_MANAGED'
    assert not (managed / OWNED_POLICY_NAME).exists()
    assert other.read_bytes() == original
    assert store.relinquish('chrome') == 'EXTERNALLY_MANAGED'


def test_foreign_extension_policy_causes_conflict_without_mutation(store):
    path = store.roots['chromium'] / 'gpo.json'
    original = b'{"ExtensionInstallForcelist":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;https://example.test/update.xml"]}'
    path.write_bytes(original)
    with pytest.raises(BrowserPolicyConflict):
        store.apply('chrome')
    assert path.read_bytes() == original
    assert not (path.parent / OWNED_POLICY_NAME).exists()
    assert not list(store.state_root.iterdir())


def test_external_endpoint_entry_is_observed_without_taking_ownership(store):
    path = store.roots['chromium'] / 'ansible.json'
    original = json.dumps({'ExtensionInstallForcelist':[EXTENSION+';'+store.update_url]}).encode()
    path.write_bytes(original)
    assert store.inspect('chromium') == ('EXTERNAL', 'APPLIED')
    assert store.relinquish('chrome') == 'EXTERNALLY_MANAGED'
    assert path.read_bytes() == original
    with pytest.raises(BrowserPolicyConflict):
        store.apply('chrome')


def test_ownership_marker_does_not_authorize_deleting_a_changed_file(store):
    store.apply('chrome')
    path = store.roots['chromium'] / OWNED_POLICY_NAME
    path.write_bytes(b'{"HomepageLocation":"https://external.test/"}')
    with pytest.raises(BrowserPolicyConflict):
        store.relinquish('chrome')
    assert path.read_bytes() == b'{"HomepageLocation":"https://external.test/"}'
    assert store.inspect('chromium') == ('CONFLICT', 'CONFLICT')


def test_marker_intent_recovers_before_or_after_owned_file_publication(store):
    store.apply('chrome')
    path = store.roots['chromium'] / OWNED_POLICY_NAME
    path.unlink()
    assert store.apply('chrome') == 'APPLIED'
    assert store.inspect('chromium') == ('ENDPOINT', 'APPLIED')
    path.unlink()
    assert store.relinquish('chrome') == 'EXTERNALLY_MANAGED'
    assert not list(store.state_root.iterdir())


@pytest.mark.parametrize('unsafe', ['symlink', 'world_writable', 'duplicate_keys'])
def test_unsafe_corporate_file_is_never_overwritten(store, unsafe):
    path = store.roots['chromium'] / 'gpo.json'
    if unsafe == 'symlink':
        target = store.state_root / 'external'
        target.write_text('{}'); path.symlink_to(target)
    else:
        path.write_bytes(b'{"ExtensionSettings":{},"ExtensionSettings":{}}' if unsafe == 'duplicate_keys' else b'{}')
        if unsafe == 'world_writable': path.chmod(0o666)
    with pytest.raises(BrowserPolicyConflict):
        store.apply('chrome')


def test_foreign_file_at_owned_name_is_not_adopted(store):
    path = store.roots['chromium'] / OWNED_POLICY_NAME
    original = b'{"HomepageLocation":"https://external.test/"}'
    path.write_bytes(original)
    with pytest.raises(BrowserPolicyConflict):
        store.apply('chrome')
    assert store.relinquish('chrome') == 'EXTERNALLY_MANAGED'
    assert path.read_bytes() == original


def test_publication_never_replaces_a_racing_external_file(store, monkeypatch):
    from pc_agent.platform.linux import browser_policy as implementation
    create = implementation._create
    original = b'{"HomepageLocation":"https://external.test/"}'
    def race(path, payload):
        if path.name == OWNED_POLICY_NAME:
            path.write_bytes(original)
        return create(path, payload)
    monkeypatch.setattr(implementation, '_create', race)
    with pytest.raises(BrowserPolicyConflict):
        store.apply('chrome')
    assert (store.roots['chromium'] / OWNED_POLICY_NAME).read_bytes() == original


def test_later_foreign_gpo_conflict_is_visible_without_another_apply(store):
    store.apply('chrome')
    path = store.roots['chromium'] / 'gpo.json'
    path.write_text('{"ExtensionInstallForcelist":["external-extension"]}')
    assert store.inspect('chromium') == ('CONFLICT', 'CONFLICT')
