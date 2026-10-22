"""Frozen TLS must retain an interpreter's required security policy resource."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


def fixture(tmp_path, source="resource = 'codex-rejected-cas.pem'", policy=True):
    module = tmp_path / 'ssl.py'
    module.write_text(source)
    if policy:
        (tmp_path / 'codex-rejected-cas.pem').write_bytes(b'public fixture policy bytes')
    return SimpleNamespace(pure=[('ssl', str(module), 'PYMODULE')], datas=[])


def test_required_tls_policy_is_collected_byte_for_byte(tmp_path):
    from tools.canary.ssl_payload import configure_ssl_resources
    analysis = fixture(tmp_path)
    binding = configure_ssl_resources(analysis)
    assert analysis.datas == [('codex-rejected-cas.pem', str(tmp_path/'codex-rejected-cas.pem'), 'DATA')]
    assert binding == {'ssl_source_sha256': hashlib.sha256((tmp_path/'ssl.py').read_bytes()).hexdigest(),
                       'resource_sha256': hashlib.sha256(b'public fixture policy bytes').hexdigest()}


def test_missing_required_tls_policy_refuses_build(tmp_path):
    from tools.canary.ssl_payload import configure_ssl_resources
    with pytest.raises(ValueError, match='TLS policy resource'):
        configure_ssl_resources(fixture(tmp_path, policy=False))


def test_standard_ssl_or_networkless_graph_adds_no_policy(tmp_path):
    from tools.canary.ssl_payload import configure_ssl_resources
    for analysis in [fixture(tmp_path, source='ordinary_ssl = True'), SimpleNamespace(pure=[], datas=[])]:
        assert configure_ssl_resources(analysis) is None
        assert analysis.datas == []


def test_alias_or_unsupported_policy_input_is_rejected(tmp_path):
    import os
    from tools.canary.ssl_payload import configure_ssl_resources
    analysis = fixture(tmp_path)
    os.link(tmp_path/'codex-rejected-cas.pem', tmp_path/'second-link.pem')
    with pytest.raises(ValueError, match='TLS policy resource'):
        configure_ssl_resources(analysis)


@pytest.mark.skipif(os.name != 'nt', reason='real frozen Windows TLS context')
def test_frozen_tls_context_retains_required_security_policy(tmp_path):
    root = Path(__file__).resolve().parents[2]
    source = tmp_path/'tls_probe.py'
    source.write_text("import ssl\nctx=ssl.create_default_context()\n"
                      "assert ctx.verify_mode == ssl.CERT_REQUIRED\n"
                      "assert ctx.check_hostname\n"
                      "assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2\n"
                      "print('verified TLS context')\n")
    spec = tmp_path/'probe.spec'
    spec.write_text(
        'import sys\nsys.path.insert(0,' + repr(str(root)) + ')\n'
        'from tools.canary.ssl_payload import configure_ssl_resources\n'
        'a=Analysis([' + repr(str(source)) + '],pathex=[],datas=[],hiddenimports=[])\n'
        'configure_ssl_resources(a)\n'
        'pyz=PYZ(a.pure)\n'
        'exe=EXE(pyz,a.scripts,exclude_binaries=True,name="tls_probe",console=True)\n'
        'collect=COLLECT(exe,a.binaries,a.datas,name="tls_probe")\n')
    built = subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--log-level=WARN',
        '--distpath', str(tmp_path/'dist'), '--workpath', str(tmp_path/'work'), str(spec)],
        capture_output=True, text=True, timeout=120)
    assert built.returncode == 0, built.stderr[-2000:]
    result = subprocess.run([str(tmp_path/'dist/tls_probe/tls_probe.exe')],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'verified TLS context'
