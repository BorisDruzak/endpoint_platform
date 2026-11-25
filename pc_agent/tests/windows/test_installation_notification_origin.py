"""Retained native facts can use the fixed Endpoint without an optional override."""
import json
import os
from pathlib import Path

import pytest

from pc_agent.tests.windows.test_installer_fence import native_protected_root
from pc_agent.tests.windows.test_installation_lifecycle import DEVICE, TX1, TX2, NATIVE, ack, add


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


@pytest.mark.parametrize(('origin', 'expected_host'), [
    (None, 'endpoint.sosnadmin.local'),
    ('https://endpoint.sosnadmin.local', 'endpoint.sosnadmin.local'),
    ('https://endpoint-staging.sosnadmin.local', 'endpoint-staging.sosnadmin.local'),
])
def test_retained_native_events_deliver_in_order_without_backfilling_origin(
    enrolled, monkeypatch, origin, expected_host,
):
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
    class Transport(notification.InstallationHTTPSClient):
        def __call__(self, event):
            assert self.ca_file == data/'endpoint-ca.crt'
            assert self._token == 'x'*43
            assert self._host == expected_host
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


def test_invalid_protected_ca_keeps_facts_pending_before_any_connection(enrolled, monkeypatch):
    from pc_agent.platform.windows import installation_notification as notification
    data, paths, box = enrolled
    add(box, action='installed')
    before = (box.root/'journal.json').read_bytes()
    monkeypatch.setattr(notification, 'outbox_for', lambda _:box)
    monkeypatch.setattr(notification.http.client, 'HTTPSConnection',
        lambda *a, **kw:pytest.fail('invalid CA reached the network'))
    # The fixture's protected CA-COPY is not a valid certificate. Use the actual
    # SSLContext and sender here, including the missing-origin default path.
    assert notification.deliver_retained(paths) == 'pending'
    assert len(box.pending(DEVICE)) == 1
    assert (box.root/'journal.json').read_bytes() == before
    assert not (data/'endpoint-origin').exists()


@pytest.mark.parametrize('outcome, expected, should_retire', [
    ('pending', 75, False), ('delivered', 0, True), ('not_applicable', 0, True),
])
def test_retry_sender_retires_only_a_settled_queue_under_the_installer_mutex(
        monkeypatch, outcome, expected, should_retire):
    from contextlib import contextmanager
    from pc_agent.platform.windows import installation_notification as notification, update_transaction
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    paths = object()
    events = []

    @contextmanager
    def transaction(actual, *, timeout_ms):
        assert actual is paths and timeout_ms == 0
        events.append('acquired')
        try:
            yield
        finally:
            events.append('released')

    monkeypatch.setattr(WindowsUpdatePaths, 'production', classmethod(lambda _: paths))
    monkeypatch.setattr(update_transaction, 'update_transaction', transaction)
    monkeypatch.setattr(notification.installer_fence, 'read_fence', lambda _: None)
    def deliver(actual):
        assert actual is paths
        events.append('delivery')
        return outcome
    monkeypatch.setattr(notification, 'deliver_retained', deliver)
    def retire(actual):
        assert actual is paths
        events.append('retired')
    monkeypatch.setattr(notification, '_retire_retry_task', retire)

    assert notification.notification_main(['--installation-events-send-retry']) == expected
    assert events == ['acquired', 'delivery', *(['retired'] if should_retire else []), 'released']


def test_retry_task_launches_only_the_bounded_sender(monkeypatch):
    from pc_agent.platform.windows import installation_notification as notification

    calls = []
    monkeypatch.setattr(notification, 'bounded_delivery',
        lambda *, retry_task: calls.append(retry_task) or 'pending')
    assert notification.notification_main(['--installation-events-retry']) == 75
    assert calls == [True]
    assert notification.notification_main(['--installation-events-retry', 'unexpected']) is None


@pytest.mark.parametrize('defect', [
    None, 'normalized-dacl', 'different-image', 'different-mode', 'multiple-actions', 'wrong-principal',
    'wrong-owner', 'foreign-ace', 'wrong-task-path', 'wrong-workdir',
    'disabled-task', 'wrong-boot-trigger', 'limited-repetition', 'changed-settings',
    'missing-admin-rights', 'inherited-rights',
])
def test_retry_retirement_checks_the_registered_task_ownership(monkeypatch, tmp_path, defect):
    import sys
    from types import SimpleNamespace
    from pc_agent.platform.windows import installation_notification as notification
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

    com = pytest.importorskip('win32com.client')
    program = tmp_path / 'endpoint-installer-host.exe'
    paths = WindowsUpdatePaths(tmp_path / 'Agent', tmp_path / 'data/updates/pending.json')
    workdir = notification.installer_fence.state_root(paths) / (
        'helper-11111111-1111-4111-8111-111111111111-' + 'a'*32)
    monkeypatch.setattr(sys, 'executable', str(program))
    monkeypatch.setattr(notification.installer_fence, 'assert_state_security', lambda path, *, secret: None)
    action = SimpleNamespace(Type=0, Path=str(program), Arguments='--installation-events-retry',
                             WorkingDirectory=str(tmp_path if defect == 'wrong-workdir' else workdir))
    if defect == 'different-image':
        action.Path = str(tmp_path / 'different.exe')
    if defect == 'different-mode':
        action.Arguments = '--installation-events-deliver'
    actions = SimpleNamespace(Count=2 if defect == 'multiple-actions' else 1,
                              Item=lambda index: action)
    system = 'S-1-5-18'
    local_service = 'S-1-5-19'
    principal = SimpleNamespace(
        UserId=local_service if defect == 'wrong-principal' else system,
        LogonType=5, RunLevel=1,
    )
    owner = 'LS' if defect == 'wrong-owner' else 'BA'
    sddl = f'O:{owner}G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    if defect == 'foreign-ace':
        sddl += '(A;;FA;;;BU)'
    if defect == 'normalized-dacl':
        # Observed from the registered Windows 10 task under LocalSystem.
        sddl = 'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;SY)'
    if defect == 'missing-admin-rights':
        sddl = sddl.replace('(A;;FA;;;BA)', '(A;;FR;;;BA)')
    if defect == 'inherited-rights':
        sddl = sddl.replace('(A;;FA;;;BA)', '(A;ID;FA;;;BA)')
    timer = SimpleNamespace(Type=1, Enabled=True, EndBoundary='',
                            Repetition=SimpleNamespace(Interval='PT1M',
                                Duration='PT5M' if defect == 'limited-repetition' else ''))
    boot = SimpleNamespace(Type=9 if defect == 'wrong-boot-trigger' else 8,
                           Enabled=True, EndBoundary='')
    triggers = SimpleNamespace(Count=2, Item=lambda index: (timer, boot)[index - 1])
    settings = SimpleNamespace(ExecutionTimeLimit='PT1M', MultipleInstances=2,
                               StartWhenAvailable=True, DisallowStartIfOnBatteries=False,
                               StopIfGoingOnBatteries=defect == 'changed-settings')
    definition = SimpleNamespace(Actions=actions, Principal=principal, Triggers=triggers, Settings=settings)
    if defect == 'normalized-dacl':
        scheduler = com.Dispatch('Schedule.Service')
        scheduler.Connect()
        definition = scheduler.NewTask(0)
        definition.Principal.UserId = system
        definition.Principal.LogonType = 5
        definition.Principal.RunLevel = 1
        definition.Settings.ExecutionTimeLimit = 'PT1M'
        definition.Settings.MultipleInstances = 2
        definition.Settings.StartWhenAvailable = True
        definition.Settings.DisallowStartIfOnBatteries = False
        definition.Settings.StopIfGoingOnBatteries = False
        native_action = definition.Actions.Create(0)
        native_action.Path = action.Path
        native_action.Arguments = action.Arguments
        native_action.WorkingDirectory = action.WorkingDirectory
        native_timer = definition.Triggers.Create(1)
        native_timer.Repetition.Interval = 'PT1M'
        definition.Triggers.Create(8)
    task = SimpleNamespace(
        Enabled=defect != 'disabled-task',
        Definition=definition,
        Path=r'\Elsewhere\EndpointInstallationEventDelivery' if defect == 'wrong-task-path'
        else r'\EndpointInstallationEventDelivery',
        GetSecurityDescriptor=lambda _: sddl,
    )
    deleted = []
    folder = SimpleNamespace(GetTask=lambda name: task,
                             DeleteTask=lambda name, flags: deleted.append((name, flags)))
    scheduler = SimpleNamespace(Connect=lambda: None, GetFolder=lambda name: folder)
    dispatch = com.Dispatch
    def registered_task_dispatch(target, *args, **kwargs):
        return scheduler if target == 'Schedule.Service' else dispatch(target, *args, **kwargs)
    monkeypatch.setattr(com, 'Dispatch', registered_task_dispatch)

    if defect in (None, 'normalized-dacl'):
        notification._retire_retry_task(paths)
        assert deleted == [('EndpointInstallationEventDelivery', 0)]
    else:
        with pytest.raises(ValueError, match='INSTALLATION_RETRY_TASK_CONFLICT'):
            notification._retire_retry_task(paths)
        assert deleted == []
