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
