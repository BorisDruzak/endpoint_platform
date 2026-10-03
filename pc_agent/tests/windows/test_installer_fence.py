"""An owner crash must not admit OTA while service-hosted MSI survives."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


@pytest.fixture(autouse=True)
def isolated_mutex(monkeypatch):
    from pc_agent.platform.windows import update_transaction
    monkeypatch.setattr(update_transaction, '_MUTEX_NAME', 'Local\\EndpointFenceTest-' + uuid4().hex)


@pytest.fixture
def native_protected_root():
    """Only our unique test directory; ordinary pytest TEMP has unsafe parents."""
    import shutil
    import win32security
    import win32file
    from pywintypes import SECURITY_ATTRIBUTES
    from win32com.shell import shell,shellcon
    parent=Path(shell.SHGetFolderPath(0,shellcon.CSIDL_PROGRAM_FILES,0,0)).resolve()
    root=parent/('EndpointTask7FenceTest-'+uuid4().hex)
    security=SECURITY_ATTRIBUTES()
    security.SECURITY_DESCRIPTOR=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',1)
    win32file.CreateDirectory(str(root),security)
    try:
        yield root
    finally:
        assert root.resolve().parent==parent and root.name.startswith('EndpointTask7FenceTest-')
        shutil.rmtree(root)


def state():
    return {"schema_version": 1, "transaction_id": str(uuid4()), "phase": "msi-executing",
        "operation": "install", "package": {"sha256": "a" * 64,
            "product_code": "{11111111-1111-4111-8111-111111111111}",
            "package_code": "{22222222-2222-4222-8222-222222222222}",
            "version": "3.2.82", "source_revision": "b" * 40},
        "selected": "c" * 64, "previous": None,
        "service_states": {"EndpointAgent": "running", "EndpointAgentUpdater": "stopped"},
        "service_startup": {"EndpointAgent":{"start_type":2,"delayed_auto":False},"EndpointAgentUpdater":{"start_type":3,"delayed_auto":False}},
        "startup_restored":False,
        "sequence": 1, "helpers": []}


@pytest.fixture
def fenced(tmp_path, monkeypatch):
    from pc_agent.platform.windows import installer_fence
    paths = WindowsUpdatePaths(tmp_path / "Agent", tmp_path / "data/updates/pending_update.json")
    directory = installer_fence.state_root(paths)
    directory.mkdir()
    monkeypatch.setattr(installer_fence, "assert_state_security", lambda *_a, **_kw: None)
    path = directory / "transaction.json"
    path.write_text(json.dumps(state()), encoding="utf-8")
    return paths, path


def test_normal_mutex_acquisition_honors_surviving_installer_fence(fenced):
    from pc_agent.platform.windows.update_transaction import UpdateInProgress, update_transaction
    paths, path = fenced
    before = path.read_bytes()
    with pytest.raises(UpdateInProgress):
        with update_transaction(paths):
            pytest.fail("ordinary mutation admitted behind installer fence")
    assert path.read_bytes() == before


@pytest.mark.parametrize("defect", ["truncated", "duplicate", "unknown_phase", "unknown_package", "secret_field"])
def test_invalid_fence_does_not_become_absence(fenced, defect):
    from pc_agent.platform.windows.update_transaction import update_transaction
    paths, path = fenced
    value = state()
    if defect == "truncated":
        data = b'{"phase":'
    elif defect == "duplicate":
        data = b'{"schema_version":1,"schema_version":1}'
    else:
        if defect == "unknown_phase": value["phase"] = "forgotten"
        elif defect == "unknown_package": value["package"]["sha256"] = "invalid"
        else: value["capability_secret"] = "must never be accepted"
        data = json.dumps(value).encode()
    path.write_bytes(data)
    with pytest.raises(ValueError, match="UPDATE_STATE_INVALID"):
        with update_transaction(paths):
            pytest.fail("invalid installer fence admitted mutation")
    assert path.read_bytes() == data


def test_fixed_host_refuses_launch_before_fence_retirement(fenced):
    from pc_agent.platform.windows.service_launcher import build_agent_child_command
    paths, _ = fenced
    with pytest.raises(ValueError, match="INSTALLER_RECOVERY_REQUIRED"):
        build_agent_child_command(paths)


def test_visible_complete_fence_still_requires_durable_retirement(fenced):
    from pc_agent.platform.windows.update_transaction import UpdateInProgress, update_transaction
    paths, path = fenced
    value = state()
    value["phase"] = "complete"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(UpdateInProgress):
        with update_transaction(paths):
            pytest.fail("visible complete journal is not a durable deletion barrier")


@pytest.mark.skipif(os.name != 'nt', reason='native abandoned Windows mutex and file ACL')
def test_owner_death_cannot_admit_writer_with_native_protected_fence(native_protected_root, monkeypatch):
    import win32event
    from pc_agent.platform.windows import installer_fence as fence, update_transaction as transaction
    paths = WindowsUpdatePaths(native_protected_root / 'Agent', native_protected_root / 'updates/pending_update.json')
    root = fence.state_root(paths)
    root.mkdir()
    fence.protect_state(root)
    fence.publish_fence(paths, state())
    before = (root / 'transaction.json').read_bytes()
    child = subprocess.Popen([sys.executable, '-c', '''
import os, sys
from pc_agent.platform.windows import update_transaction as t
t._MUTEX_NAME=sys.argv[1]
with t._windows_transaction(0):
    print('owned', flush=True)
    sys.stdin.readline()
    os._exit(73)
''', transaction._MUTEX_NAME], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    retained = None
    try:
        assert child.stdout.readline().strip() == 'owned'
        retained = win32event.OpenMutex(0x120001, False, transaction._MUTEX_NAME)
        child.communicate('exit\n', timeout=20)
        assert child.returncode == 73
        results = []
        original = win32event.WaitForSingleObject
        def observed(handle, timeout):
            result = original(handle, timeout)
            results.append(result)
            return result
        monkeypatch.setattr(win32event, 'WaitForSingleObject', observed)
        with pytest.raises(transaction.UpdateInProgress, match='INSTALLER_RECOVERY_REQUIRED'):
            with transaction.update_transaction(paths, timeout_ms=0):
                pytest.fail('abandoned native owner bypassed protected fence')
        assert results == [win32event.WAIT_ABANDONED]
    finally:
        if child.poll() is None:
            child.kill(); child.wait(timeout=20)
        if retained is not None:
            retained.Close()
    assert (root / 'transaction.json').read_bytes() == before


@pytest.mark.skipif(os.name != 'nt', reason='native protected fence ACL validation')
def test_native_fence_rejects_unrelated_writer_without_repair(native_protected_root):
    import win32security
    from pc_agent.platform.windows import installer_fence as fence
    paths = WindowsUpdatePaths(native_protected_root / 'Agent', native_protected_root / 'updates/pending_update.json')
    root = fence.state_root(paths)
    root.mkdir()
    fence.protect_state(root)
    fence.publish_fence(paths, state())
    path = root / 'transaction.json'
    before = path.read_bytes()
    acl = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;FA;;;WD)', 1).GetSecurityDescriptorDacl()
    win32security.SetNamedSecurityInfo(str(path), 1,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, acl, None)
    with pytest.raises(ValueError, match='UPDATE_STATE_INVALID'):
        fence.read_fence(paths)
    assert path.read_bytes() == before
