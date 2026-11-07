"""Execute the spec against build API recorders; inspect resolved import closure."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_frozen_support_spec_resolves_only_independent_runtime(tmp_path, monkeypatch):
    from tools.release import freeze_linux_native_identity
    identity = tmp_path/'linux-native-build.json'
    identity.write_text('{"schema_version":"endpoint_linux_native_build_v1"}')
    monkeypatch.setattr(freeze_linux_native_identity, 'freeze_identity', lambda *_: str(identity))
    captured = {}
    class Analysis:
        def __init__(self,scripts,**kwargs):
            captured.update(kwargs,scripts=scripts)
            self.pure=[]; self.binaries=[]; self.scripts=scripts; self.datas=[]
    namespace=dict(SPECPATH=str(ROOT/'pc_agent'),Analysis=Analysis,
        PYZ=lambda *_:None,EXE=lambda *a,**k:captured.update(exe=k),
        COLLECT=lambda *a,**k:captured.update(collect=k))
    spec=ROOT/'pc_agent/pyinstaller_linux_support_access.spec'
    exec(compile(spec.read_text(),str(spec),'exec'),namespace)
    assert captured['exe']['name'] == 'endpoint-support-access'
    assert Path(captured['scripts'][0]).is_file()
    assert captured['collect']['name'] == 'endpoint-support-access'
    assert captured['datas'] == [(str(identity),'.')]
    pending=['pc_agent.platform.linux.support_access_service']
    seen=set()
    while pending:
        name=pending.pop()
        if name in seen:
            continue
        seen.add(name)
        module=ROOT.joinpath(*name.split('.')).with_suffix('.py')
        for node in ast.walk(ast.parse(module.read_text())):
            if isinstance(node,ast.ImportFrom) and node.module and node.module.startswith('pc_agent.'):
                pending.append(node.module)
            if isinstance(node,ast.Import):
                pending.extend(alias.name for alias in node.names if alias.name.startswith('pc_agent.'))
    assert seen == {'pc_agent.platform.linux.support_access_service','pc_agent.platform.linux.support_access',
        'pc_agent.platform.linux.support_access_native','pc_agent.platform.linux.enrollment_origin',
        'pc_agent.platform.linux.native_build_identity'}
