"""The privileged browser-policy service loads one packaged extension ID."""

from __future__ import annotations

import json
import runpy
import sys
import pytest
from pathlib import Path

from pc_agent.platform.windows.browser_policy import CHROME_POLICY_PATH
from pc_agent.platform.windows.browser_policy_service_entry import (
    load_packaged_extension_id,
    make_policy_listener,
)
from pc_agent.tests.windows.test_browser_policy import EXTENSION_ID, MemoryRegistry


@pytest.fixture(autouse=True)
def isolated_machine_paths(tmp_path,monkeypatch):
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'package/Agent',tmp_path/'data/updates/pending_update.json')
    monkeypatch.setattr(WindowsUpdatePaths,'production',classmethod(lambda cls:paths))


def test_service_entry_imports_when_run_as_frozen_main_script() -> None:
    """PyInstaller executes its Analysis script without a package context."""
    entry = Path(__file__).resolve().parents[2] / "platform/windows/browser_policy_service_entry.py"
    namespace = runpy.run_path(str(entry), run_name="frozen_main_import_smoke")
    assert callable(namespace["run_browser_policy_service"])


def test_service_entry_loads_only_packaged_extension_identity(
    monkeypatch, tmp_path
) -> None:
    bundle = tmp_path / "bundle"
    identity = bundle / "browser_sensor" / "extension-id.txt"
    identity.parent.mkdir(parents=True)
    identity.write_text(EXTENSION_ID, encoding="ascii")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    assert load_packaged_extension_id() == EXTENSION_ID
    identity.write_text("malformed", encoding="ascii")
    try:
        load_packaged_extension_id()
    except ValueError:
        pass
    else:
        raise AssertionError("malformed packaged extension identity accepted")


def test_service_listener_authenticates_then_applies_only_packaged_id(
    monkeypatch,
) -> None:
    registry = MemoryRegistry()
    calls: list[str] = []
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.WindowsPolicyRegistry",
        lambda: registry,
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.load_packaged_extension_id",
        lambda: EXTENSION_ID,
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_service_entry.authorize_agent_pipe_client",
        lambda _handle: calls.append("authorized"),
    )
    listener = make_policy_listener()
    reply = listener._on_frame(
        object(),
        b'{"schema_version":"endpoint_browser_policy_request_v1","operation":"apply","browser_family":"chrome"}',
    )
    assert calls == ["authorized"]
    assert json.loads(reply)["status"] == "APPLIED"
    assert EXTENSION_ID in json.loads(
        registry.read(CHROME_POLICY_PATH, "ExtensionSettings")
    )


def test_pending_installer_blocks_policy_listener_before_registry_access(monkeypatch):
    from pc_agent.platform.windows import installer_fence
    constructed=[]
    def blocked(_paths):raise ValueError('INSTALLER_RECOVERY_REQUIRED')
    monkeypatch.setattr(installer_fence,'assert_launch_allowed',blocked)
    monkeypatch.setattr('pc_agent.platform.windows.browser_policy_service_entry.WindowsPolicyRegistry',
        lambda:constructed.append('registry'))
    with pytest.raises(ValueError,match='INSTALLER_RECOVERY_REQUIRED'):make_policy_listener()
    assert constructed==[]


def test_new_installer_barrier_blocks_existing_policy_listener_frame(monkeypatch):
    from pc_agent.platform.windows import installer_fence
    registry=MemoryRegistry();blocked=[False]
    def gate(_paths):
        if blocked[0]:raise ValueError('INSTALLER_RECOVERY_REQUIRED')
    monkeypatch.setattr(installer_fence,'assert_launch_allowed',gate)
    monkeypatch.setattr('pc_agent.platform.windows.browser_policy_service_entry.WindowsPolicyRegistry',lambda:registry)
    monkeypatch.setattr('pc_agent.platform.windows.browser_policy_service_entry.load_packaged_extension_id',lambda:EXTENSION_ID)
    monkeypatch.setattr('pc_agent.platform.windows.browser_policy_service_entry.authorize_agent_pipe_client',lambda _:None)
    listener=make_policy_listener();blocked[0]=True
    # The listener's service boundary may report the denial; no registry write
    # is permitted even though it started before the installer barrier appeared.
    try:listener._on_frame(object(),b'{"schema_version":"endpoint_browser_policy_request_v1","operation":"apply","browser_family":"chrome"}')
    except ValueError as error:assert str(error)=='INSTALLER_RECOVERY_REQUIRED'
    assert registry.read(CHROME_POLICY_PATH,'ExtensionSettings') is None


def test_trial_policy_does_not_rehash_runtime_for_each_pipe_request(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from pc_agent.platform.windows import browser_policy_service_entry as entry
    from pc_agent.platform.windows import installer_fence, staged_update_state, service_launcher
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths = WindowsUpdatePaths.production()
    paths.install_root.mkdir(parents=True)
    selector = {'schema_version': 1, 'version': '3.2.123', 'source_revision': 'a' * 40}
    paths.current_path.write_text(json.dumps(selector))
    binding = SimpleNamespace(candidate_tree_sha256='b' * 64, selected_tree_sha256_before='c' * 64)
    record = SimpleNamespace(phase='trial', binding=binding)
    monkeypatch.setattr(staged_update_state, 'read_staged_update', lambda _: record)
    monkeypatch.setattr(installer_fence, 'assert_launch_allowed', lambda _: None)
    monkeypatch.setattr(installer_fence, 'assert_state_security', lambda _: None)
    checks = []
    monkeypatch.setattr(staged_update_state, 'assert_staged_update_allowed', lambda *a, **k: checks.append('phase'))
    verified = []
    monkeypatch.setattr(service_launcher, '_verify_selected_runtime', lambda *a: verified.append(a[1]))
    monkeypatch.setattr(entry, 'WindowsPolicyRegistry', MemoryRegistry)
    monkeypatch.setattr(entry, 'load_packaged_extension_id', lambda: EXTENSION_ID)
    monkeypatch.setattr(entry, 'authorize_agent_pipe_client', lambda _: None)
    listener = make_policy_listener()
    frame = b'{"schema_version":"endpoint_browser_policy_request_v1","operation":"apply","browser_family":"chrome"}'
    for _ in range(2):
        assert json.loads(listener._on_frame(object(), frame))['status'] == 'APPLIED'
    assert verified == [selector]
    assert len(checks) == 3
    # The cache never bypasses a later phase or selection change.
    record.phase = 'switching'
    with pytest.raises(ValueError, match='STAGED_UPDATE_IN_PROGRESS'):
        listener._on_frame(object(), frame)
    record.phase = 'trial'
    selector['source_revision'] = 'd' * 40
    paths.current_path.write_text(json.dumps(selector))
    listener._on_frame(object(), frame)
    assert len(verified) == 2
