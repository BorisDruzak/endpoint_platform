"""MSI owns a staged helper; active Support remains outside native lifetime."""
import hashlib
import json
from dataclasses import replace
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]
NS = {'w': 'http://wixtoolset.org/schemas/v4/wxs'}


def test_native_package_never_owns_or_controls_active_support():
    tree = ET.parse(ROOT / 'packaging/windows/wix/Services.wxs')
    component = tree.find(".//w:Component[@Id='cmpSupportAccess']", NS)
    assert component.attrib['Directory'] == 'INSTALLFOLDER'
    assert component.find("w:File[@Id='filSupportAccess']", NS).attrib['Source'].endswith(r'ProgramFiles\EndpointSupportAccess.exe')
    assert component.find('w:ServiceControl', NS) is None
    assert component.find('w:ServiceInstall', NS) is None
    assert component.find('w:RemoveFolder', NS) is None
    assert component.find('w:CreateFolder', NS) is None
    directories = ET.parse(ROOT / 'packaging/windows/wix/Directories.wxs')
    assert directories.find(".//w:Directory[@Id='SUPPORTINSTALLFOLDER']", NS) is None
    removal = tree.find(".//w:Custom[@Action='CommitSupportAccessRemoval']", NS)
    for gate in ('NOT UPGRADINGPRODUCTCODE', 'NOT ENDPOINT_STAGED_REMOVE', 'NOT ENDPOINT_UNINSTALL_FINALIZE'):
        assert gate in removal.attrib['Condition']


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    from pc_agent.platform.windows import msi_inventory as module
    from pc_agent.tests.windows.test_installation_provenance import payload
    from pc_agent.tests.windows.test_msi_inventory import package
    from pc_agent.platform.windows.foundation_layout import shared_binding
    manifest = payload(tmp_path)
    contract = (tmp_path / 'endpoint-runtime-contract.json').read_bytes()
    original = package(module)
    files = [module.InstalledFile(row['path'], 'core', 'versions/3.2.82/' + row['path'], row['size']) for row in manifest['files']]
    files += [module.InstalledFile('manifest', 'core', 'versions/3.2.82/endpoint-update-manifest.json', 1),
              module.InstalledFile('marker', 'core', 'versions/3.2.82/.endpoint-msi-runtime.json', 1)]
    components = dict(original.components)
    rows = []
    helper = b'signed independent helper model'
    bindings = {**module.FOUNDATION_EXECUTABLES,
                'EndpointSupportAccess.exe': ('filSupportAccess', 'cmpSupportAccess'),
                '_foundation-runtime/python312.dll': shared_binding('_foundation-runtime/python312.dll')}
    for name, (file_id, component) in bindings.items():
        raw = helper if name == 'EndpointSupportAccess.exe' else b'payload'
        components[component] = module.Component(component,
            '{C20F6D8B-2DF2-42E6-9C7C-0D033D137F61}', 'INSTALLFOLDER', file_id, (module.FOUNDATION_FEATURE,))
        files.append(module.InstalledFile(file_id, component, name, len(raw)))
        rows.append(dict(path=name, file=file_id, component=component, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    current = replace(original, files=tuple(files), components=components)
    streams = {'EndpointInitialRuntimeInventory': {'schema_version': 3, 'manifest': manifest,
               'contract_bytes': contract.hex(), 'foundation_files': rows},
               'EndpointSupportAccessRemoval': helper}
    monkeypatch.setattr(module, 'read_package', lambda *_: current)
    def binary(_path, name, **_kwargs):
        return json.dumps(streams[name]).encode() if isinstance(streams[name], dict) else streams[name]
    monkeypatch.setattr(module, 'read_binary', binary)
    tree = hashlib.sha256()
    for row in sorted(manifest['files'], key=lambda row: 'endpoint_agent_core.exe' if row['path'] == 'pc_agent.exe' else row['path']):
        name = 'endpoint_agent_core.exe' if row['path'] == 'pc_agent.exe' else row['path']
        tree.update(f"{name}\0{row['size']}\0{row['sha256']}\n".encode())
    release = dict(schema_version='endpoint_windows_release_v1', version='3.2.82', source_revision='a'*40,
        package_sha256='a'*64, product_code=current.product_code, initial_runtime_tree_sha256=tree.hexdigest())
    return module, tmp_path / 'candidate.msi', release, streams, current


def test_schema3_covers_staged_helper_and_exact_embedded_uninstaller(inventory):
    module, path, release, _, _ = inventory
    expected = module.read_expected_package(path, release)
    assert expected.foundation_schema == 3
    assert any(row['path'] == 'EndpointSupportAccess.exe' for row in expected.foundation_files)


@pytest.mark.parametrize('defect', ['missing', 'hash', 'size', 'binary', 'schema1', 'schema2', 'keypath', 'feature'])
def test_schema3_rejects_unbound_helper_or_removal_code(inventory, monkeypatch, defect):
    module, path, release, streams, package = inventory
    metadata = streams['EndpointInitialRuntimeInventory']
    row = next(row for row in metadata['foundation_files'] if row['path'] == 'EndpointSupportAccess.exe')
    if defect == 'missing':
        metadata['foundation_files'].remove(row)
    elif defect == 'hash':
        row['sha256'] = 'f' * 64
    elif defect == 'size':
        row['size'] += 1
    elif defect == 'binary':
        streams['EndpointSupportAccessRemoval'] = b'foreign cleanup code'
    elif defect.startswith('schema'):
        metadata['schema_version'] = int(defect[-1])
    else:
        component = package.components['cmpSupportAccess']
        changed = replace(component, keypath='foreign') if defect == 'keypath' else replace(component, features=(module.RUNTIME_FEATURE,))
        monkeypatch.setattr(module, 'read_package', lambda *_: replace(package, components={**package.components, 'cmpSupportAccess': changed}))
    with pytest.raises(module.ProvenanceConflict):
        module.read_expected_package(path, release)


@pytest.mark.parametrize('defect', ['none', 'helper-bytes', 'extra-shared-file'])
def test_schema3_pins_helper_bytes_and_preserves_shared_namespace_gate(inventory, monkeypatch, tmp_path, defect):
    from pc_agent.platform.windows import update_transaction
    module, path, release, streams, _ = inventory
    expected = module.read_expected_package(path, release)
    installed = tmp_path / 'installed'
    installed.mkdir()
    for row in expected.foundation_files:
        target = installed / row['path']
        target.parent.mkdir(exist_ok=True, parents=True)
        target.write_bytes(streams['EndpointSupportAccessRemoval'] if row['path'] == 'EndpointSupportAccess.exe' else b'payload')
    # Only the native ACL boundary is modeled; retained handles, complete hashes
    # and the schema3 shared-directory/file-set gate all execute here.
    monkeypatch.setattr(update_transaction, '_assert_state_security', lambda _: None)
    if defect == 'helper-bytes':
        (installed / 'EndpointSupportAccess.exe').write_bytes(b'foreign helper')
    elif defect == 'extra-shared-file':
        (installed / '_foundation-runtime/foreign.dll').write_bytes(b'extra')
    if defect == 'none':
        with module.verified_foundation_bytes(expected, installed):
            pass
    else:
        with pytest.raises(ValueError):
            with module.verified_foundation_bytes(expected, installed):
                pytest.fail('unverified helper/shared namespace reached native authority')


@pytest.mark.parametrize('remaining', ['none', 'image', 'service', 'foreign-image'])
def test_support_aware_normal_uninstall_requires_active_channel_absence(inventory, tmp_path, remaining):
    from types import SimpleNamespace
    module, path, release, _, _ = inventory
    expected = module.read_expected_package(path, release)
    install_root = tmp_path / 'product/Agent'
    image = install_root.parent / 'Support/EndpointSupportAccess.exe'
    if remaining in {'image', 'foreign-image'}:
        image.parent.mkdir(parents=True)
        image.write_bytes(b'foreign' if remaining == 'foreign-image' else b'owned-active-image')
    native = SimpleNamespace(support_service_absent=lambda: remaining != 'service')
    if remaining == 'none':
        module.verify_support_uninstalled(expected, install_root, native=native)
    else:
        with pytest.raises(ValueError, match='SUPPORT_CLEANUP_INCOMPLETE'):
            module.verify_support_uninstalled(expected, install_root, native=native)
        if image.exists():
            assert image.read_bytes() == (b'foreign' if remaining == 'foreign-image' else b'owned-active-image')


def test_historical_foundation_uninstall_never_inspects_independent_support(inventory, tmp_path):
    from types import SimpleNamespace
    module, path, release, _, _ = inventory
    expected = replace(module.read_expected_package(path, release), foundation_schema=2)
    module.verify_support_uninstalled(expected, tmp_path / 'Agent', native=SimpleNamespace(
        support_service_absent=lambda: pytest.fail('historical MSI inspected independent Support')))


@pytest.mark.parametrize('mode', ['staged-remove', 'compound', 'normal', 'install', 'retire'])
def test_postcommit_support_absence_gate_is_normal_uninstall_only(monkeypatch, mode):
    from types import SimpleNamespace
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, msi_inventory
    calls = []
    monkeypatch.setattr(msi_inventory, 'verify_support_uninstalled', lambda *args: calls.append('absence'))
    cap = {'operation': 'uninstall'}
    if mode == 'staged-remove':
        cap['staged_rollback'] = {'role': 'remove'}
    elif mode == 'compound':
        cap['compound'] = {}
    elif mode in {'install', 'retire'}:
        cap['operation'] = 'install' if mode == 'install' else 'retire-initial-runtime'
    bridge._verify_normal_support_uninstall(SimpleNamespace(foundation_schema=3), SimpleNamespace(install_root=Path('Agent')), cap)
    assert calls == (['absence'] if mode == 'normal' else [])


def test_support_cleanup_failure_has_a_distinct_bounded_diagnostic_code(inventory, tmp_path):
    from types import SimpleNamespace
    from pc_agent.platform.windows.installer_phase_diagnostics import _exception_context
    module, path, release, _, _ = inventory
    expected = module.read_expected_package(path, release)
    def denied():
        raise PermissionError('do not expose native infrastructure details')
    with pytest.raises(ValueError, match='SUPPORT_CLEANUP_INCOMPLETE') as failure:
        module.verify_support_uninstalled(expected, tmp_path / 'Agent', native=SimpleNamespace(support_service_absent=denied))
    context = _exception_context(failure.value)
    assert context['safe_code'] == 'SUPPORT_CLEANUP_INCOMPLETE'
    assert 'infrastructure' not in str(context)


@pytest.mark.parametrize('intent,native,status,expected', [
    ('uninstall', 0, 'incomplete', 68), ('uninstall', 68, 'incomplete', 0),
    ('install', 0, 'incomplete', 0), ('uninstall', 0, 'complete', 0),
    ('uninstall', 0, 'legacy', 0)])
def test_owner_cleanup_exit68_requires_normal_uninstall_known0_and_finish_ack(tmp_path, intent, native, status, expected):
    import subprocess
    script = tmp_path / 'cleanup-result.ps1'
    script.write_text('''param($Source,$Intent,[int]$Native,$Status)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw $errors[0]}
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SupportCleanupExitCode'},$true)
Invoke-Expression $node.Extent.Text
$finish=if($Status -eq 'legacy'){@{}}else{@{result='native-uninstalled';support_cleanup=$Status}}
Get-SupportCleanupExitCode -Intent $Intent -NativeExit $Native -Finish $finish
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script),
        str(ROOT / 'packaging/windows/Install-EndpointAgentCanary.ps1'), intent, str(native), status],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == str(expected)


@pytest.mark.parametrize('native,expected', [(68, 21), (0, 0), (67, 67), (3010, 3010)])
def test_raw_native_exit_cannot_impersonate_reserved_cleanup68(tmp_path, native, expected):
    import subprocess
    script = tmp_path / 'native-result.ps1'
    script.write_text('''param($Source,[int]$Native)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw $errors[0]}
$node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-NativeWrapperExitCode'},$true)
Invoke-Expression $node.Extent.Text
$original=$Native
$result=Get-NativeWrapperExitCode -NativeExit $Native
if($Native -ne $original){throw 'native journal result changed'}
$result
''', encoding='utf-8')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script),
        str(ROOT / 'packaging/windows/Install-EndpointAgentCanary.ps1'), str(native)],
        capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == str(expected)
