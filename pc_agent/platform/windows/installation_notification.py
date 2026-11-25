"""Bounded notification from Setup, provisioning or the retry task.

The authenticated native owner records facts before fence retirement. The
notification process enters its own installer transaction after native helper
completion.
"""
from __future__ import annotations

import http.client
import json
from pathlib import Path
import re
import ssl
import sys
import time

from endpoint_contracts.runtime_payload import read_json
from endpoint_contracts.installation_lifecycle import InstallationEventV1, InstallationEventAckV1
from . import installer_fence
from .installation_lifecycle import _identity, outbox_for

_ORIGIN = 'https://endpoint.sosnadmin.local'
_RETRY_TASK = 'EndpointInstallationEventDelivery'
_RETRY_MODE = '--installation-events-retry'
_RETRY_SEND_MODE = '--installation-events-send-retry'
_INSTALLATION_HOSTS = {
    _ORIGIN: 'endpoint.sosnadmin.local',
    'https://endpoint-staging.sosnadmin.local': 'endpoint-staging.sosnadmin.local',
}


class InstallationHTTPSClient:
    """Fixed origin, pinned CA, no redirects/proxies; one bounded foreground run."""
    def __init__(self, ca_file, token, *, origin=_ORIGIN):
        if origin not in _INSTALLATION_HOSTS or not re.fullmatch('[A-Za-z0-9_-]{43}', token):
            raise ValueError('INSTALLATION_AUTHORITY_UNAVAILABLE')
        self._host = _INSTALLATION_HOSTS[origin]
        self._token, self.ca_file = token, ca_file
        self._deadline = time.monotonic()+20

    def __call__(self, event):
        event = InstallationEventV1.model_validate(event).model_dump(mode='json')
        remaining = self._deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('INSTALLATION_DELIVERY_PENDING')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=str(self.ca_file))
        connection = http.client.HTTPSConnection(self._host,443,
            context=context, timeout=min(8, remaining))
        try:
            connection.request('POST','/agent/v1/installation-events',
                body=json.dumps(event,separators=(',',':')).encode('utf-8'),
                headers={'Authorization':'Bearer '+self._token,'Content-Type':'application/json'})
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError('INSTALLATION_DELIVERY_PENDING')
            raw = bytearray()
            while len(raw) <= 4096:
                remaining = self._deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('INSTALLATION_DELIVERY_PENDING')
                if connection.sock is not None:
                    connection.sock.settimeout(min(8,remaining))
                chunk = response.read1(4097-len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            return InstallationEventAckV1.model_validate(read_json(bytes(raw),4096)).model_dump(mode='json')
        finally:
            connection.close()


def _sender(data_root):
    from .support_bootstrap import assert_bootstrap_file, read_optional_bootstrap_ascii
    from pc_agent.device_credential import read_device_credential
    for name in ('device-credential','endpoint-ca.crt'):
        assert_bootstrap_file(data_root/name)
    origin = read_optional_bootstrap_ascii(data_root/'endpoint-origin', default=_ORIGIN)
    return InstallationHTTPSClient(data_root/'endpoint-ca.crt',
        read_device_credential(data_root/'device-credential'), origin=origin)


def deliver_retained(paths):
    """Only local protected authority; failures never change native outcome."""
    try:
        box = outbox_for(paths)
        if box._load() is None:
            return 'not_applicable'
        data_root = paths.pending_path.parents[1]
        device = _identity(data_root)
        if not box.pending(device):
            return 'delivered'
        return box.deliver(device, _sender(data_root))
    except Exception:
        return 'pending'


def sync_enrolled_installation(data_root):
    """Setup/provisioning retry before Support activation, under the native lock.

    Fresh install facts bind only to the durable identity now present. Previously
    bound removal facts retain their original identity forever, including wipes.
    """
    from .update_paths import WindowsUpdatePaths
    from .update_transaction import update_transaction
    try:
        paths = WindowsUpdatePaths.production()
        if paths.pending_path.parents[1] != data_root:
            raise ValueError('INSTALLATION_AUTHORITY_UNAVAILABLE')
        with update_transaction(paths, timeout_ms=0):
            if installer_fence.read_fence(paths) is not None:
                return 'pending'
            box = outbox_for(paths)
            loaded = box._load()
            if loaded is None:
                return 'not_applicable'
            device = _identity(data_root)
            facts = loaded[1]['facts']
            if facts and facts[-1]['action']=='installed' and facts[-1]['device_id'] is None:
                # Both credential and identity must be durable and protected.
                _sender(data_root)
                box.bind_installation(facts[-1]['transaction_id'], device)
            if not box.pending(device):
                return 'delivered'
        # The notification-only child must acquire its own transaction lock.
        # Binding is already durable; never wait for networking under this lock.
        return bounded_delivery()
    except Exception:
        return 'pending'


def _run_notification_process(arguments, *, timeout_ms=20000):
    """Contain only a new notification process, including onefile descendants.

    Suspension precedes Job assignment. A timeout, coordinator crash or handle
    close terminates that Job; native MSI/helper processes are never members.
    """
    import win32event
    import win32job
    import win32process
    from .support_access_native import NativeProcessJob
    job = NativeProcessJob()
    status = 'pending'
    try:
        job.launch(arguments)
        process = job.processes[0]
        if win32event.WaitForSingleObject(process, timeout_ms) == win32event.WAIT_OBJECT_0:
            if win32process.GetExitCodeProcess(process) == 0:
                status = 'delivered'
    finally:
        try:
            # Also reap an unexpected surviving descendant after parent exit.
            if job.job:
                win32job.TerminateJobObject(job.job, 75)
                deadline = time.monotonic()+5
                while win32job.QueryInformationJobObject(job.job,
                        win32job.JobObjectBasicAccountingInformation)['ActiveProcesses']:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('INSTALLATION_NOTIFICATION_REAP_PENDING')
                    time.sleep(0.01)
        finally:
            job.close()
    return status


def bounded_delivery(*, retry_task=False):
    """Wait for a contained notification child."""
    mode = _RETRY_SEND_MODE if retry_task else '--installation-events-send'
    if getattr(sys, 'frozen', False):
        command = [sys.executable, mode]
    else:
        # NativeProcessJob uses the interpreter's directory as cwd. Source-only
        # runs therefore bind this checkout explicitly instead of ambient cwd.
        source_root = str(Path(__file__).resolve().parents[3])
        command = [sys.executable, '-c',
            'import sys;sys.path.insert(0,'+repr(source_root)+');'
            'from pc_agent.platform.windows.installer_host_entry import main;'
            'raise SystemExit(main('+repr([mode])+'))']
    try:
        return _run_notification_process(command)
    except Exception:
        return 'pending'


def _retire_retry_task(paths):
    """Called while the installer mutex still protects the drained queue."""
    import ntsecuritycon
    import win32security
    from win32com.client import Dispatch
    from .scheduled_task import find_task

    scheduler = Dispatch('Schedule.Service')
    scheduler.Connect()
    folder = scheduler.GetFolder('\\')
    task = find_task(folder, _RETRY_TASK)
    if task is None:
        return
    definition = task.Definition
    actions = definition.Actions
    if task.Path.casefold() != ('\\' + _RETRY_TASK).casefold() or actions.Count != 1:
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
    action = actions.Item(1)
    if action.Type != 0 or Path(action.Path) != Path(sys.executable) or action.Arguments != _RETRY_MODE:
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
    triggers = definition.Triggers
    settings = definition.Settings
    if (not task.Enabled or triggers.Count != 2 or settings.ExecutionTimeLimit != 'PT1M'
            or settings.MultipleInstances != 2 or not settings.StartWhenAvailable
            or settings.DisallowStartIfOnBatteries or settings.StopIfGoingOnBatteries):
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
    timer, boot = triggers.Item(1), triggers.Item(2)
    if (timer.Type != 1 or not timer.Enabled or timer.Repetition.Interval != 'PT1M'
            or timer.Repetition.Duration or timer.EndBoundary
            or boot.Type != 8 or not boot.Enabled or boot.EndBoundary):
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
    workdir = Path(action.WorkingDirectory)
    if (workdir.parent != installer_fence.state_root(paths)
            or not re.fullmatch(r'helper-[0-9a-f-]{36}-[0-9a-f]{32}', workdir.name)):
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
    installer_fence.assert_state_security(workdir, secret=True)

    principal = definition.Principal
    sid = (win32security.ConvertStringSidToSid(principal.UserId) if principal.UserId.startswith('S-1-')
           else win32security.LookupAccountName(None, principal.UserId)[0])
    if win32security.ConvertSidToStringSid(sid) != 'S-1-5-18' or principal.LogonType != 5 or principal.RunLevel != 1:
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')

    rights = {'S-1-5-18': 0, 'S-1-5-32-544': 0}
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(task.GetSecurityDescriptor(7), 1)
    owner, acl = descriptor.GetSecurityDescriptorOwner(), descriptor.GetSecurityDescriptorDacl()
    if owner is None or win32security.ConvertSidToStringSid(owner) not in rights or acl is None:
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
    # Task Scheduler can omit SE_DACL_PROTECTED and add a SYSTEM read ACE
    # when serializing the task. Validate the actual explicit effective ACL.
    full = ntsecuritycon.FILE_ALL_ACCESS
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if len(ace) != 3:
            raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
        kind, mask, sid = ace
        identity = win32security.ConvertSidToStringSid(sid)
        if kind != (win32security.ACCESS_ALLOWED_ACE_TYPE, 0) or identity not in rights or mask & ~full:
            raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
        rights[identity] |= mask
    if any(mask != full for mask in rights.values()):
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')

    folder.DeleteTask(_RETRY_TASK, 0)


def notification_main(argv=None):
    """Fixed private modes accept no facts, paths, credential or native capability."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ['--installation-events-deliver']:
        return 0 if bounded_delivery() == 'delivered' else 75
    if arguments == [_RETRY_MODE]:
        return 0 if bounded_delivery(retry_task=True) == 'delivered' else 75
    if arguments not in (['--installation-events-send'], [_RETRY_SEND_MODE]):
        return None
    from .update_paths import WindowsUpdatePaths
    from .update_transaction import update_transaction
    try:
        paths = WindowsUpdatePaths.production()
        with update_transaction(paths, timeout_ms=0):
            if installer_fence.read_fence(paths) is not None:
                return 75
            result = deliver_retained(paths)
            if result not in {'delivered', 'not_applicable'}:
                return 75
            if arguments == [_RETRY_SEND_MODE]:
                _retire_retry_task(paths)
            return 0
    except Exception:
        return 75
