"""Volatile HKLM markers survive owner loss; missing witnesses are not reboot proof."""
import os
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest


@pytest.mark.parametrize('value', ['', '20261020125508.151071+300',
    'kernel-boot-v1:11111111-1111-4111-8111-111111111111',
    'registry-boot-v1:00000000-0000-0000-0000-000000000000',
    'registry-boot-v1:AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'])
def test_noncanonical_or_historical_marker_is_not_reboot_authority(value):
    from pc_agent.platform.windows import staged_boot_marker as marker
    assert marker.valid_token(value) is False


@pytest.fixture
def native_marker(tmp_path):
    if os.name != 'nt': pytest.skip('actual private HKLM witness and native owner')
    import winreg
    from pc_agent.platform.windows import staged_boot_marker as marker
    operation = str(uuid4())
    source = Path(__file__).resolve().parents[3] / 'packaging/windows/Install-EndpointAgentCanary.ps1'
    script = tmp_path / 'marker.ps1'
    script.write_text(r'''param($Source,$Operation)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'owner parse failure'}
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-InstallerBridgeTypes'},$true)
Invoke-Expression $node.Extent.Text;Initialize-InstallerBridgeTypes
[EndpointInstallerBridge.BootMarker]::Capture($Operation)
''', encoding='utf-8')
    def capture():
        return subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(source),operation],
                              capture_output=True,text=True,timeout=30)
    try:
        result = capture()
        assert result.returncode == 0, result.stderr
        yield marker, operation, result.stdout.strip(), capture
    finally:
        # Only this fixture's random operation namespace; production never
        # removes witnesses or live markers as part of installer cleanup.
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, marker.ROOT+'\\'+operation, 0,
                                winreg.KEY_ALL_ACCESS|winreg.KEY_WOW64_64KEY) as key:
                children = [winreg.EnumKey(key, index) for index in range(winreg.QueryInfoKey(key)[0])]
                assert len(children) <= 16
                for child in children:
                    assert child.startswith('boot-') and str(__import__('uuid').UUID(child[5:])) == child[5:]
                    winreg.DeleteKeyEx(key, child, winreg.KEY_WOW64_64KEY)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, marker.ROOT, 0, winreg.KEY_ALL_ACCESS|winreg.KEY_WOW64_64KEY) as root:
                winreg.DeleteKeyEx(root, operation, winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            pass


def test_native_marker_survives_creator_exit_and_uses_exact_private_witness(native_marker):
    marker, operation, token, _ = native_marker
    assert marker.valid_token(token)
    assert marker.present(operation, token) is True
    from pc_agent.platform.windows import durable_state
    with durable_state.installer_mutation_checkpoints(lambda: None):
        second = marker.capture(operation)
    assert second != token
    assert marker.present(operation, token) and marker.present(operation, second)


def test_initial_capture_cannot_reuse_existing_witness(native_marker):
    marker, operation, token, capture = native_marker
    assert capture().returncode != 0
    assert marker.present(operation, token)


def test_only_missing_leaf_with_intact_witness_counts_as_new_boot(native_marker):
    import winreg
    marker, operation, token, _ = native_marker
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, marker.ROOT+'\\'+operation, 0,
                        winreg.KEY_ALL_ACCESS|winreg.KEY_WOW64_64KEY) as witness:
        winreg.DeleteKeyEx(witness, 'boot-'+token.split(':')[1], winreg.KEY_WOW64_64KEY)
    assert marker.present(operation, token) is False
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, marker.ROOT, 0,
                        winreg.KEY_ALL_ACCESS|winreg.KEY_WOW64_64KEY) as root:
        winreg.DeleteKeyEx(root, operation, winreg.KEY_WOW64_64KEY)
    with pytest.raises(ValueError, match='RECOVERY_REQUIRED'):
        marker.present(operation, token)


def test_marker_creation_requires_live_mutation_checkpoint(native_marker):
    marker, operation, _, _ = native_marker
    with pytest.raises(ValueError):
        marker.capture(operation)


@pytest.mark.parametrize('code',[5,1018])
def test_access_failure_or_deleted_handle_is_never_absence(native_marker,monkeypatch,code):
    import win32api,pywintypes
    marker,operation,token,_=native_marker
    original=win32api.RegOpenKeyEx
    def open_key(parent,name,*args):
        if name.startswith('boot-'):raise pywintypes.error(code,'RegOpenKeyEx','injected failure')
        return original(parent,name,*args)
    monkeypatch.setattr(win32api,'RegOpenKeyEx',open_key)
    with pytest.raises(ValueError,match='RECOVERY_REQUIRED'):marker.present(operation,token)


def test_changed_witness_acl_is_not_reboot_proof(native_marker):
    import winreg,win32security
    marker,operation,token,_=native_marker
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,marker.ROOT+'\\'+operation,0,
                        winreg.KEY_ALL_ACCESS|winreg.KEY_WOW64_64KEY) as key:
        descriptor=win32security.GetSecurityInfo(int(key),win32security.SE_REGISTRY_KEY,7)
        dacl=descriptor.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAceEx(2,2,winreg.KEY_READ,win32security.ConvertStringSidToSid('S-1-5-19'))
        win32security.SetSecurityInfo(int(key),win32security.SE_REGISTRY_KEY,
            win32security.PROTECTED_DACL_SECURITY_INFORMATION|win32security.DACL_SECURITY_INFORMATION,None,None,dacl,None)
    with pytest.raises(ValueError,match='RECOVERY_REQUIRED'):marker.present(operation,token)


def test_dangling_registry_link_is_not_missing_marker(native_marker):
    import winreg,win32api,win32con,win32security,pywintypes
    marker,operation,token,_=native_marker
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,marker.ROOT+'\\'+operation,0,
                        winreg.KEY_ALL_ACCESS|winreg.KEY_WOW64_64KEY) as parent:
        name='boot-'+token.split(':')[1]
        winreg.DeleteKeyEx(parent,name,winreg.KEY_WOW64_64KEY)
        sa=pywintypes.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR=win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(marker._SDDL,1)
        try:key,created=win32api.RegCreateKeyEx(int(parent),name,winreg.KEY_ALL_ACCESS|winreg.KEY_WOW64_64KEY,Options=2,SecurityAttributes=sa)
        except pywintypes.error as error:
            if error.winerror==1314:pytest.skip('registry link privilege unavailable')
            raise
        try:
            assert created==1
            target='\\Registry\\Machine\\'+marker.ROOT+'\\missing-'+str(uuid4())
            winreg.SetValueEx(int(key),'SymbolicLinkValue',0,6,target.encode('utf-16-le'))
        finally:key.Close()
    with pytest.raises(ValueError,match='RECOVERY_REQUIRED'):marker.present(operation,token)
