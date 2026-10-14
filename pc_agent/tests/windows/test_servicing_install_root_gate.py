"""Servicing permissions apply only to the fixed directory observer."""
import os
import pytest
from pc_agent.platform.windows import update_transaction as gate, installer_fence
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='native Windows security descriptors')
TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

@pytest.fixture
def roots(tmp_path, monkeypatch):
    import win32security as security
    paths = WindowsUpdatePaths(tmp_path/'Agent', tmp_path/'data/updates/pending_update.json')
    paths.install_root.mkdir(); paths.updates_root.mkdir(parents=True)
    def descriptor(path, *_):
        writer, flags = writers.get(str(path), ('S-1-5-18', 0))
        acl = security.ACL()
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, flags, 0x1f01ff, security.ConvertStringSidToSid(writer))
        sd = security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid('S-1-5-18'), False)
        sd.SetSecurityDescriptorDacl(True, acl, False)
        return sd
    writers = {str(paths.install_root): (TI, 0)}
    monkeypatch.setattr(security, 'GetNamedSecurityInfo', descriptor)
    monkeypatch.setattr(installer_fence, 'assert_namespace_security', lambda _: None)
    return paths, writers

@pytest.mark.parametrize('writer,flags', [(TI, 0), ('S-1-3-0', 8)])
def test_idle_gate_accepts_servicing_directory_without_mutation(roots, writer, flags):
    paths, writers = roots
    writers[str(paths.install_root)] = (writer, flags)
    before = paths.install_root.stat().st_mtime_ns
    assert gate.active_update_state(paths) is None
    assert paths.install_root.stat().st_mtime_ns == before

@pytest.mark.parametrize('role', ['data', 'updates', 'journal', 'selector'])
def test_servicing_exception_does_not_extend_to_data_or_files(roots, role):
    paths, writers = roots
    target = {'data': paths.updates_root.parent, 'updates': paths.updates_root,
              'journal': paths.pending_path, 'selector': paths.restore_path}[role]
    if role in ('journal', 'selector'):
        target.write_text('{"operation_id":"x","version":"3.2.79"}')
    writers[str(target)] = (TI, 0)
    with pytest.raises(ValueError):
        gate.active_update_state(paths)

@pytest.mark.parametrize('defect', ['ordinary-writer', 'file-root', 'namespace'])
def test_servicing_root_cannot_bypass_directory_or_namespace_security(roots, monkeypatch, defect):
    paths, writers = roots
    if defect == 'ordinary-writer': writers[str(paths.install_root)] = ('S-1-5-32-545', 0)
    elif defect == 'file-root': paths.install_root.rmdir(); paths.install_root.write_bytes(b'file')
    else: monkeypatch.setattr(installer_fence, 'assert_namespace_security', lambda _: (_ for _ in ()).throw(ValueError('parent writer')))
    with pytest.raises(ValueError):
        gate.active_update_state(paths)

def test_modern_service_writer_directory_keeps_existing_policy(roots):
    paths, writers = roots
    writers[str(paths.install_root)] = (gate._SERVICE_SIDS[1], 0)
    assert gate.active_update_state(paths) is None

@pytest.mark.parametrize('role,expected', [('install', 'IDLE'), ('data', 'INVALID'), ('journal', 'INVALID')])
def test_powershell_gate_confines_servicing_acl_to_install_directory(tmp_path, role, expected):
    import subprocess
    from pathlib import Path
    paths = WindowsUpdatePaths(tmp_path/'Agent', tmp_path/'data/updates/pending_update.json')
    paths.install_root.mkdir(); paths.updates_root.mkdir(parents=True)
    if role == 'journal': paths.pending_path.write_text('{"operation_id":"x","version":"3.2.79"}')
    script = tmp_path/'gate.ps1'
    script.write_text(r'''param($Source,$Install,$Data,$Role)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Parse failed'}
foreach($node in $tree.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) { Invoke-Expression $node.Extent.Text }
$script:UpdateTrustedOwners=@('S-1-5-18','S-1-5-32-544')
# Ancestor trust is a separately tested native boundary. This test supplies
# controlled descriptors to exercise the real PowerShell ACL/root routing.
Add-Type 'namespace EndpointInstallerBridge { public static class LaunchDirectory { public static void ValidateAncestors(string path) {} } }'
function Initialize-InstallerBridgeTypes {}
function Get-Acl {
 param($LiteralPath)
 $ti='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
 $target=if($Role -eq 'install'){$Install}elseif($Role -eq 'data'){$Data}else{Join-Path $Data 'updates\pending_update.json'}
 $writer=if($LiteralPath -eq $target){$ti}else{'S-1-5-18'}
 $acl=[Security.AccessControl.DirectorySecurity]::new()
 $acl.SetSecurityDescriptorSddlForm("O:SYD:P(A;;FA;;;$writer)")
 return $acl
}
try { if(Test-ActiveUpdateState $Install $Data){'ACTIVE'}else{'IDLE'} } catch {'INVALID'}
''')
    source = Path(__file__).resolve().parents[3]/'packaging/windows/Install-EndpointAgentCanary.ps1'
    result = subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'), '-NoProfile', '-File', str(script), str(source), str(paths.install_root), str(paths.updates_root.parent), role], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected, result.stderr
