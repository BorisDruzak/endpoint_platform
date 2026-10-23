"""Boot admission must survive wall-clock/WMI provider changes without a reboot."""
import ctypes
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from uuid import UUID

import pytest

from pc_agent.platform.windows import durable_state, staged_recovery as recovery
from pc_agent.tests.windows.test_staged_recovery import recovery as recovery_fixture
from pc_agent.tests.windows.test_staged_update_state import staged, move, native_protected_root

BOOT_A = 'kernel-boot-v1:11111111-1111-4111-8111-111111111111'
BOOT_B = 'kernel-boot-v1:22222222-2222-4222-8222-222222222222'


@pytest.mark.parametrize('captured,current,expected', [
    ('20261020125508.151071+300', '20261021161917.633209+300', 'rollback-required'),
    ('20261020125508.151071+300', BOOT_A, 'rollback-required'),
    (BOOT_A, BOOT_A, 'rollback-required'),
    (BOOT_A, BOOT_B, 'trial-required'),
    (BOOT_A, '20261021161917.633209+300', 'rollback-required'),
    ('kernel-boot-v1:00000000-0000-0000-0000-000000000000', BOOT_B, 'rollback-required'),
])
def test_only_different_kernel_boot_ids_authorize_new_trial(recovery_fixture, staged, monkeypatch,
                                                           captured, current, expected):
    module, paths, binding, cap = recovery_fixture
    move(staged, 'preparing', 'prepared'); move(staged, 'prepared', 'switching')
    monkeypatch.setattr(module, '_validate_recovery_inputs', lambda *_: {'boot': captured})
    monkeypatch.setattr(module, '_boot_identity', lambda: current)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        assert module.recover_staged_update(paths, binding.operation_id, capability=cap) == expected


@pytest.mark.parametrize('status,length,identifier', [
    (-1073741821, 32, UUID(BOOT_A.split(':')[1])),
    (0, 16, UUID(BOOT_A.split(':')[1])),
    (0, 32, UUID(int=0)),
])
def test_kernel_boot_query_rejects_failure_truncation_and_zero(monkeypatch, status, length, identifier):
    def query(kind, buffer, size, returned):
        assert kind == 90 and size == 32
        ctypes.memmove(buffer, identifier.bytes_le, 16)
        ctypes.cast(returned, ctypes.POINTER(ctypes.c_uint32))[0] = length
        return status
    call = SimpleNamespace()
    class Query:
        def __call__(self, *args): return query(*args)
    call.NtQuerySystemInformation = Query()
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *_args, **_kw: call, raising=False)
    with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
        recovery._boot_identity()


def test_legacy_reboot_marker_cannot_be_released_by_clock_change(recovery_fixture, staged, monkeypatch):
    module, paths, binding, _ = recovery_fixture
    move(staged, 'preparing', 'prepared'); move(staged, 'prepared', 'switching')
    monkeypatch.setattr(module, '_boot_identity', lambda: '20261020125508.151071+300')
    with durable_state.installer_mutation_checkpoints(lambda: None):
        module.record_reboot_required(paths, binding.operation_id, 3010)
        monkeypatch.setattr(module, '_boot_identity', lambda: BOOT_B)
        assert module.reboot_pending(paths, module.state.read_staged_update(paths))


@pytest.mark.skipif(os.name != 'nt', reason='real Windows kernel and signed owner ABI')
def test_powershell_and_python_capture_same_kernel_boot_identity(tmp_path):
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'boot.ps1'
    script.write_text(r'''param($Source)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'owner parse failure'}
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
[EndpointInstallerBridge.BootIdentity]::Read()
''', encoding='utf-8')
    before = recovery._boot_identity()
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script), str(source)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == before == recovery._boot_identity()
    assert before.startswith('kernel-boot-v1:')
    owner = source.read_text(encoding='utf-8')
    assert 'boot=[EndpointInstallerBridge.BootIdentity]::Read()' in owner
    assert 'LastBootUpTime' not in owner
