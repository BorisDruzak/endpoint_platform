"""Resume an enrolled Windows reinstall after its native events reach Gateway."""
from datetime import datetime, timedelta
from pathlib import Path
import re
import sys
from uuid import UUID

from . import durable_state, installer_fence
from .installation_lifecycle import _identity, outbox_for
from .installation_notification import bounded_delivery
from .installation_provenance import verified_foundation_release
from .msi_inventory import _file_sha256
from .update_paths import WindowsUpdatePaths
from .update_transaction import update_transaction

MODE = '--resume-offline-reinstall'
_TASK_PREFIX = 'EndpointSupportReinstall-'
_TASK_SDDL = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'


def _current_reinstall(paths):
    loaded = outbox_for(paths)._load()
    if loaded is None:
        return None
    device = _identity(paths.pending_path.parents[1])
    last = [fact for fact in loaded[1]['facts'] if fact['device_id'] == device][-2:]
    if (len(last) == 2 and last[0]['action'] == 'removed'
            and last[0]['cleanup']['support'] == 'complete' and last[1]['action'] == 'installed'):
        return last[1]
    return None


def _verify_release(paths, fact):
    native = fact['native']
    release = verified_foundation_release(paths)
    if (release is None or release['package_sha256'] != native['msi_sha256']
            or any(release[key] != native[key] for key in ('product_code', 'version', 'source_revision'))):
        raise ValueError('INSTALLATION_RETRY_RELEASE_CONFLICT')


def _cache_root(paths):
    return paths.install_root.parent / 'installer-cache'


def _cached_setup(paths, fact):
    return _cache_root(paths) / ('msi-' + fact['native']['msi_sha256']) / 'EndpointAgentSetup.exe'


def _running_setup(paths):
    executable = Path(sys.executable)
    if (not getattr(sys, 'frozen', False) or executable.name.casefold() != 'endpointagentsetup.exe'
            or executable.parent.parent != _cache_root(paths)
            or not re.fullmatch(r'msi-[0-9a-f]{64}', executable.parent.name)):
        raise ValueError('INSTALLATION_RETRY_MEDIA_CONFLICT')
    installer_fence.assert_state_security(executable, secret=True)
    return executable


def _authorized_fact(paths, event_id, executable):
    fact = _current_reinstall(paths)
    if (fact is not None and fact['event']['event_id'] == event_id
            and _cached_setup(paths, fact) == executable):
        return fact
    return None


def _folder():
    from win32com.client import Dispatch
    scheduler = Dispatch('Schedule.Service')
    scheduler.Connect()
    return scheduler.GetFolder('\\')


def _get_task(folder, event_id, executable):
    from pywintypes import com_error
    try:
        task = folder.GetTask(_TASK_PREFIX + event_id)
    except com_error as error:
        if (error.hresult & 0xffffffff) != 0x80070002:
            raise
        return None
    actions = task.Definition.Actions
    if actions.Count != 1:
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
    action = actions.Item(1)
    if (action.Type != 0 or Path(action.Path) != executable
            or action.Arguments != f'{MODE} {event_id}'):
        raise ValueError('INSTALLATION_RETRY_TASK_CONFLICT')
    return task


def schedule_retry(data_root):
    """Only settled, same-device native reinstalls can schedule Support."""
    if not getattr(sys, 'frozen', False):
        return
    paths = WindowsUpdatePaths.production()
    if paths.pending_path.parents[1] != data_root:
        raise ValueError('INSTALLATION_AUTHORITY_UNAVAILABLE')
    with update_transaction(paths, timeout_ms=0):
        fact = _current_reinstall(paths)
        if fact is None:
            return
        _verify_release(paths, fact)
        executable = _cached_setup(paths, fact)
        installer_fence.assert_state_security(executable, secret=True)
        # The wrapper authenticated and copied the signed Setup before native entry.
        # Bind the durable task to that protected copy of this exact executable.
        with durable_state._pinned_copy_source(executable), durable_state._pinned_copy_source(Path(sys.executable)):
            if _file_sha256(executable) != _file_sha256(Path(sys.executable)):
                raise ValueError('INSTALLATION_RETRY_MEDIA_CONFLICT')
            _register(fact['event']['event_id'], executable)


def _register(event_id, executable):
    from win32com.client import Dispatch
    scheduler = Dispatch('Schedule.Service')
    scheduler.Connect()
    folder = scheduler.GetFolder('\\')
    if _get_task(folder, event_id, executable) is not None:
        return
    definition = scheduler.NewTask(0)
    definition.RegistrationInfo.Description = 'Resume Endpoint Support after an offline native reinstall'
    definition.Principal.UserId = 'SYSTEM'
    definition.Principal.LogonType = 5
    definition.Principal.RunLevel = 1
    settings = definition.Settings
    settings.Enabled = True
    # A native Support dependency can have its own durable Windows servicing witness.
    settings.ExecutionTimeLimit = 'PT0S'
    settings.MultipleInstances = 2
    settings.StartWhenAvailable = True
    settings.DisallowStartIfOnBatteries = False
    settings.StopIfGoingOnBatteries = False
    timer = definition.Triggers.Create(1)
    timer.StartBoundary = (datetime.now().astimezone() + timedelta(seconds=15)).isoformat(timespec='seconds')
    timer.Repetition.Interval = 'PT1M'
    definition.Triggers.Create(8)
    action = definition.Actions.Create(0)
    action.Path = str(executable)
    action.Arguments = f'{MODE} {event_id}'
    action.WorkingDirectory = str(executable.parent)
    folder.RegisterTaskDefinition(_TASK_PREFIX + event_id, definition, 2, 'SYSTEM', None, 5, _TASK_SDDL)


def resume(event_id, activate):
    """Deliver first, then recheck native authority before invoking Support."""
    try:
        if str(UUID(event_id)) != event_id:
            return 75
        paths = WindowsUpdatePaths.production()
        executable = _running_setup(paths)
        folder = _folder()
        name = _TASK_PREFIX + event_id
        with update_transaction(paths, timeout_ms=0):
            if _get_task(folder, event_id, executable) is None:
                return 0
            if _authorized_fact(paths, event_id, executable) is None:
                folder.DeleteTask(name, 0)
                return 0
        if bounded_delivery() != 'delivered':
            return 75
        with update_transaction(paths, timeout_ms=0):
            if _get_task(folder, event_id, executable) is None:
                return 0
            fact = _authorized_fact(paths, event_id, executable)
            if fact is not None:
                if fact['ack'] is None:
                    return 75
                _verify_release(paths, fact)
                if not activate(paths.pending_path.parents[1]):
                    return 75
            folder.DeleteTask(name, 0)
            return 0
    except Exception:
        return 75
