"""Release gates for the dedicated privileged offline worker."""
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_msi_updater_has_its_own_executable_component():
    root = ET.parse(ROOT / 'packaging/windows/wix/Services.wxs').getroot()
    ns = {'w': 'http://wixtoolset.org/schemas/v4/wxs'}
    component = next(c for c in root.findall('.//w:Component', ns)
                     if c.find("w:ServiceInstall[@Name='EndpointAgentUpdater']", ns) is not None)
    assert component.find('w:File', ns).get('Name') == 'endpoint-agent-updater.exe'
    assert component.find("w:ServiceInstall[@Name='EndpointAgent']", ns) is None


@pytest.mark.parametrize('name', ['socket', 'socket._socket', '_socket.pyd',
    'ssl', '_ssl.cp314-win_amd64.pyd', 'http.client', 'urllib.request',
    'aiohttp.client', 'httpx', 'requests.sessions', 'asyncio.base_events',
    'internal/libssl-3-x64.dll'])
def test_offline_bundle_rejects_python_and_native_network_capabilities(name):
    from tools.canary.offline_updater_contract import assert_offline_modules
    with pytest.raises(ValueError, match='network'):
        assert_offline_modules(['json', 'hashlib', name])


def test_offline_bundle_allows_hashing_and_url_parsing():
    from tools.canary.offline_updater_contract import assert_offline_modules
    assert_offline_modules(['json', 'hashlib', '_hashlib.pyd', 'libcrypto-3-x64.dll',
                            'urllib.parse', 'win32service.pyd'])


def test_msi_builder_validates_dedicated_worker_even_when_reusing_builds():
    script = (ROOT / 'packaging/windows/build-msi.ps1').read_text(encoding='utf-8')
    assert 'pyinstaller_windows_updater.spec' in script
    gate = script.index('tools.canary.offline_updater_contract')
    reuse_end = script.index('$builtCore = ')
    stage = script.index("Copy-Item -LiteralPath $builtUpdater")
    assert reuse_end < gate < stage
    assert "binary = 'ProgramFiles/endpoint-agent-updater.exe'" in script


def _durable_dependency_names(source, *, relative_ok=False):
    """Gate the primitive's imports; local/network wrappers are forbidden too."""
    import ast

    tree = ast.parse(source)
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert relative_ok or node.level == 0, 'durable state must not import local wrappers'
            names.append(node.module or '')
    return names


def test_durable_state_dependency_gate():
    from tools.canary.offline_updater_contract import assert_offline_modules

    source = (ROOT / 'pc_agent/platform/windows/durable_state.py').read_text(encoding='utf-8')
    names = _durable_dependency_names(source)
    assert_offline_modules(names)
    # Closed dependencies prevent an innocent-looking project wrapper from
    # indirectly bringing the network runtime into the privileged worker.
    assert set(names) <= {'__future__', 'collections.abc', 'json', 'os', 'pathlib',
                          'stat', 'uuid', 'win32con', 'win32file', 'pywintypes',
                          'contextlib', 'contextvars', 'hashlib', 'msvcrt', 're'}
    for parent in ['pc_agent/__init__.py', 'pc_agent/platform/__init__.py',
                   'pc_agent/platform/windows/__init__.py']:
        if (ROOT / parent).exists():
            dependencies = _durable_dependency_names((ROOT / parent).read_text(encoding='utf-8'), relative_ok=True)
            assert dependencies == (['service_control'] if parent.endswith('windows/__init__.py') else [])
    # The Windows package initializer already imports this SCM-only boundary.
    # Gate its lazy imports as well so an indirect runtime/network import fails.
    service_names = _durable_dependency_names(
        (ROOT / 'pc_agent/platform/windows/service_control.py').read_text(encoding='utf-8'))
    assert_offline_modules(service_names)
    assert set(service_names) <= {'__future__', 'os', 'subprocess', 'dataclasses', 'pathlib',
                                  'typing', 'win32con', 'win32security', 'win32service', 'win32serviceutil'}


def test_migrated_offline_worker_project_import_graph_is_closed_to_network():
    import ast
    from importlib.util import resolve_name
    from tools.canary.offline_updater_contract import assert_offline_modules

    pending = ['pc_agent.platform.windows.updater_entry', 'pc_agent.platform.windows.service_launcher']
    visited = set()
    while pending:
        module = pending.pop()
        if module in visited:
            continue
        path = ROOT.joinpath(*module.split('.')).with_suffix('.py')
        if not path.exists():
            path = ROOT.joinpath(*module.split('.'), '__init__.py')
        if not path.exists():
            continue
        visited.add(module)
        package = module if path.name == '__init__.py' else module.rpartition('.')[0]
        for count in range(1, len(module.split('.'))):
            pending.append('.'.join(module.split('.')[:count]))
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8-sig'))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = resolve_name('.' * node.level + (node.module or ''), package) if node.level else (node.module or '')
                names = [base, *(base + '.' + alias.name for alias in node.names)]
            else:
                continue
            assert_offline_modules(names)
            pending.extend(name for name in names if name.startswith('pc_agent.'))
    assert {'pc_agent.platform.windows.acl', 'pc_agent.platform.windows.durable_state',
            'pc_agent.platform.windows.selector_migration'} <= visited
    assert 'pc_agent.update_adapter' not in visited
    assert 'pc_agent.platform.windows.online_update_runtime' not in visited


@pytest.mark.parametrize('name', ['socket', 'ssl', 'http', 'urllib.request', 'aiohttp',
                                  'httpx', 'requests', 'websockets', 'asyncio', 'libssl-3-x64.dll'])
def test_durable_state_dependency_gate_rejects_network(name):
    from tools.canary.offline_updater_contract import assert_offline_modules

    names = [name] if name.endswith('.dll') else _durable_dependency_names(f'import {name}')
    with pytest.raises(ValueError, match='network'):
        assert_offline_modules(names)


def test_durable_state_fresh_process_has_no_indirect_network_imports():
    import subprocess
    import sys

    script = '''import builtins, sys
sys.path.insert(0, sys.argv[1])
original = builtins.__import__
forbidden = ('socket', '_socket', 'ssl', '_ssl', 'http', 'urllib.request', 'aiohttp',
             'httpx', 'requests', 'websockets', 'asyncio', '_asyncio')
def offline_import(name, *args, **kwargs):
    if any(name == prefix or name.startswith(prefix + '.') for prefix in forbidden):
        raise AssertionError('indirect network import: ' + name)
    return original(name, *args, **kwargs)
builtins.__import__ = offline_import
from pc_agent.platform.windows import durable_state
from pc_agent.platform.windows import updater_service, selector_migration, acl
import tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    durable_state.write_json_atomic(root / 'state', [{'offline': True}], trusted_root=root, max_bytes=100)
    durable_state.durable_unlink(root / 'state', trusted_root=root)
    selector = root / 'current.json'
    selector.write_text('{"version":"0.0.1"}')
    selector_migration._write_selector_atomic(selector, '0.0.2')
'''
    result = subprocess.run([sys.executable, '-I', '-c', script, str(ROOT)],
                            check=True, capture_output=True, text=True)
    assert result.stdout == result.stderr == ''
