import json
import os
from pathlib import Path
import pytest


@pytest.mark.skipif(os.name != 'posix', reason='native RPM ownership/modes require Linux')
def test_native_manifest_binds_setup_support_and_sensor_in_common_payload(tmp_path):
    from tools.build_linux_native_manifest import build_manifest
    root = tmp_path/'root'
    files = {'opt/endpoint-agent/versions/3.2.180/manifest.json': b'{"source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
        'usr/lib/endpoint-agent-setup/endpoint-agent-setup': b'setup',
        'usr/lib/endpoint-support-access/endpoint-support-access': b'support',
        'usr/lib/endpoint-agent/start-user-sensor': b'sensor'}
    for name, value in files.items():
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(0o644)
    value = build_manifest(root, version='3.2.180', revision='a'*40, sensor=True)
    assert '/usr/lib/endpoint-agent-setup/endpoint-agent-setup' in value['packages']['endpoint-agent']
    assert '/usr/lib/endpoint-support-access/endpoint-support-access' in value['packages']['endpoint-agent']
    assert list(value['packages']['endpoint-agent-user-sensor']) == ['/usr/lib/endpoint-agent/start-user-sensor']
    assert (root/'usr/share/endpoint-agent/native-source.json').read_bytes() == (root/'usr/share/endpoint-agent-user-sensor/native-source.json').read_bytes()
    with pytest.raises(ValueError):
        build_manifest(root, version='3.2.180', revision='b'*40, sensor=True)
