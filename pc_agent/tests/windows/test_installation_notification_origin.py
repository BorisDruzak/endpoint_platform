"""Retained native facts can use the fixed Endpoint without an optional override."""
import json
import os
from pathlib import Path

import pytest

from pc_agent.tests.windows.test_installer_fence import native_protected_root
from pc_agent.tests.windows.test_installation_lifecycle import DEVICE, TX1, TX2, NATIVE, ack


@pytest.fixture
def enrolled(native_protected_root):
    from pc_agent.platform.windows import installer_fence, installation_lifecycle
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    data = native_protected_root/'data'
    data.mkdir()
    values = {'device-credential': 'x'*43, 'endpoint-ca.crt': 'CA-COPY',
              'enrollment-identity.json': json.dumps({'schema_version':
                  'endpoint_enrollment_identity_v1', 'device_id': DEVICE})}
    for name, value in values.items():
        path = data/name
        path.write_text(value, encoding='ascii')
        installer_fence.protect_state(path, secret=True)
    paths = WindowsUpdatePaths(native_protected_root/'Agent', data/'updates/pending.json')
    owner = native_protected_root/'installer-state'
    owner.mkdir()
    installer_fence.protect_state(owner)
    box = installation_lifecycle.NativeLifecycleOutbox(owner/'installation-events')
    return data, paths, box


@pytest.mark.parametrize('origin', [None, 'https://endpoint.sosnadmin.local'])
def test_retained_native_events_deliver_in_order_without_backfilling_origin(enrolled, monkeypatch, origin):
    from datetime import UTC, datetime
    from pc_agent.platform.windows import installation_notification as notification, installer_fence
    data, paths, box = enrolled
    if origin is not None:
        (data/'endpoint-origin').write_text(origin, encoding='ascii')
        installer_fence.protect_state(data/'endpoint-origin', secret=True)
    facts = []
    for tx, version in ((TX1, '3.2.177'), (TX2, '3.2.186')):
        facts.append(box.record(transaction_id=tx, action='installed', device_id=DEVICE,
            native={**NATIVE, 'version': version}, cleanup={'support':'complete','browser':'complete'},
            occurred_at=datetime(2026, 11, 7, tzinfo=UTC)))
    before = {p.name:p.read_bytes() for p in data.iterdir()}
    anchor = (box.root/'anchor.json').read_bytes()
    sent = []
    class Transport:
        def __init__(self, ca_file, token):
            assert ca_file == data/'endpoint-ca.crt' and token == 'x'*43
        def __call__(self, event):
            sent.append(event)
            return ack(event)
    monkeypatch.setattr(notification, 'InstallationHTTPSClient', Transport)
    monkeypatch.setattr(notification, 'outbox_for', lambda _:box)
    assert notification.deliver_retained(paths) == 'delivered'
    assert sent == facts
    assert [e['native']['version'] for e in sent] == ['3.2.177', '3.2.186']
    assert box.pending(DEVICE) == []
    assert (box.root/'anchor.json').read_bytes() == anchor
    assert {p.name:p.read_bytes() for p in data.iterdir()} == before


@pytest.mark.parametrize('defect', ['foreign', 'empty', 'malformed', 'directory', 'dangling',
    'hardlink', 'unsafe-acl', 'denied-stat', 'denied-read', 'missing-parent',
    'missing-credential', 'invalid-credential', 'missing-ca', 'unsafe-ca'])
def test_missing_override_does_not_hide_other_authority_failures(enrolled, monkeypatch, defect):
    from pc_agent.platform.windows import installation_notification as notification, installer_fence
    data, _, _ = enrolled
    origin = data/'endpoint-origin'
    if defect in {'foreign','empty','malformed','unsafe-acl','denied-stat','denied-read'}:
        origin.write_text({'foreign':'https://foreign.example', 'empty':'',
            'malformed':'http://endpoint.sosnadmin.local'}.get(defect,
                'https://endpoint.sosnadmin.local'), encoding='ascii')
        installer_fence.protect_state(origin, secret=True)
    if defect == 'directory': origin.mkdir()
    if defect == 'dangling': origin.symlink_to(data/'absent-target')
    if defect == 'hardlink': os.link(data/'endpoint-ca.crt', origin)
    if defect.startswith('missing-'):
        if defect == 'missing-parent': data = data/'absent-parent'
        else: (data/('device-credential' if defect=='missing-credential' else 'endpoint-ca.crt')).unlink()
    if defect == 'invalid-credential': (data/'device-credential').write_text('invalid', encoding='ascii')
    if defect in {'unsafe-acl','unsafe-ca'}:
        import win32security as security
        target = origin if defect=='unsafe-acl' else data/'endpoint-ca.crt'
        sd = security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;FA;;;WD)',1)
        security.SetNamedSecurityInfo(str(target), security.SE_FILE_OBJECT,
            security.DACL_SECURITY_INFORMATION|security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,None,sd.GetSecurityDescriptorDacl(),None)
    if defect in {'denied-stat','denied-read'}:
        method = 'lstat' if defect=='denied-stat' else 'read_text'
        original = getattr(Path, method)
        def denied(path, *args, **kwargs):
            if path == origin: raise PermissionError('denied')
            return original(path,*args,**kwargs)
        monkeypatch.setattr(Path,method,denied)
    monkeypatch.setattr(notification,'InstallationHTTPSClient',
        lambda *args:pytest.fail('invalid authority reached the transport'))
    with pytest.raises((OSError,ValueError)):
        notification._sender(data)


@pytest.mark.parametrize('defect', ['missing', 'file', 'denied'])
def test_optional_leaf_requires_accessible_real_parent(tmp_path, monkeypatch, defect):
    from pc_agent.platform.windows.support_bootstrap import read_optional_bootstrap_ascii
    parent = tmp_path/'parent'
    if defect == 'file': parent.write_text('not a directory', encoding='ascii')
    if defect == 'denied':
        parent.mkdir()
        original = Path.stat
        def denied(path, *args, **kwargs):
            if path == parent: raise PermissionError('denied')
            return original(path, *args, **kwargs)
        monkeypatch.setattr(Path, 'stat', denied)
    with pytest.raises((OSError, ValueError)):
        read_optional_bootstrap_ascii(parent/'endpoint-origin', default='https://endpoint.sosnadmin.local')
