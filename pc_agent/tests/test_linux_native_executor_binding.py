"""The Setup/source binding applies to every source except the immutable156 pair."""
from dataclasses import replace

import pytest

from pc_agent.platform.linux.installation_lifecycle import InstallationPending
from tools.release.linux_native_verifier import (VerifiedNativeRPM, PUBLISHER, LEGACY_SOURCE,
    LEGACY_MANIFEST, LEGACY_RPMS)


def proof(version='3.2.179'):
    return VerifiedNativeRPM('endpoint-agent-'+version+'-alt6.x86_64',PUBLISHER,'a'*40,'b'*64,
        'c'*64,version,'endpoint-agent','d'*64)


def binding(native, sensor=False):
    return {'version':native.version,'source_revision':native.source_revision,'core_nevra':native.nevra,
        'core_rpm_sha256':native.sha256,'user_sensor_nevra':'endpoint-agent-user-sensor-3.2.156-alt5.x86_64' if sensor else None,
        'user_sensor_rpm_sha256':LEGACY_RPMS['endpoint-agent-user-sensor'] if sensor else None}


def test_corrected179_setup_can_execute_only_its_signed_source():
    from pc_agent.platform.linux.installation_coordinator import assert_executor_binding
    native = proof()
    executor = {'sha256':'d'*64,'source_revision':'a'*40,'version':'3.2.179'}
    assert_executor_binding(binding(native), native, executor)
    for wrong in ({'sha256':'e'*64}, {'source_revision':'f'*40}, {'version':'3.2.178'}):
        with pytest.raises(InstallationPending): assert_executor_binding(binding(native),native,executor | wrong)


@pytest.mark.parametrize('version', ['3.2.178','3.2.180','3.2.156'])
def test_other_modern_sources_cannot_skip_setup_binding_by_version(version):
    from pc_agent.platform.linux.installation_coordinator import assert_executor_binding
    native = proof(version)
    with pytest.raises(InstallationPending):
        assert_executor_binding(binding(native),native,{'sha256':'d'*64,'source_revision':'a'*40,'version':'3.2.179'})
    with pytest.raises(InstallationPending):
        assert_executor_binding(binding(native),replace(native,setup_sha256=None),{'sha256':None,'source_revision':'a'*40,'version':version})


@pytest.mark.parametrize('sensor', [True, False])
def test_only_exact_historical156_source_has_setup_exemption(sensor):
    from pc_agent.platform.linux.installation_coordinator import assert_executor_binding
    native = VerifiedNativeRPM('endpoint-agent-3.2.156-alt5.x86_64',PUBLISHER,LEGACY_SOURCE,
        LEGACY_MANIFEST,LEGACY_RPMS['endpoint-agent'],'3.2.156','endpoint-agent')
    assert_executor_binding(binding(native,sensor),native,{'version':'3.2.179'})
    for changed in ({'core_rpm_sha256':'1'*64},{'core_nevra':'endpoint-agent-3.2.156-alt6.x86_64'},
        {'source_revision':'2'*40},{'user_sensor_rpm_sha256':'3'*64},
        {'user_sensor_nevra':'endpoint-agent-user-sensor-3.2.156-alt6.x86_64'}):
        with pytest.raises(InstallationPending):
            assert_executor_binding(binding(native,sensor) | changed,native,{'version':'3.2.179'})

@pytest.mark.parametrize('version', ['3.2.179','3.2.180','3.2.156'])
def test_cli_refuses_mismatched_modern_source_before_any_native_work(monkeypatch, version):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as c, installation_notification as n
    from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore
    store = MemoryStore()
    store.prepare = lambda: None
    store.locked = nullcontext
    store.data['executor.json'] = {'sha256':'e'*64,'source_revision':'a'*40,'version':'3.2.179'}
    monkeypatch.setattr(c,'os',SimpleNamespace(name='posix',geteuid=lambda:0))
    monkeypatch.setattr(c,'InstallationStore',lambda:store)
    monkeypatch.setattr(c,'retain_executor',lambda *_:None)
    monkeypatch.setattr(c,'retain_inputs',lambda paths,*_:paths)
    monkeypatch.setattr(c,'NativeRPMVerifier',lambda *_args,**_kw:lambda _:proof(version))
    monkeypatch.setattr(n,'canonical_identity',lambda:(None,None))
    invoked = []
    monkeypatch.setattr(c.NativeCoordinator,'operate',lambda *_args,**_kw:invoked.append(True))
    monkeypatch.setattr(c.subprocess,'run',lambda *_args,**_kw:SimpleNamespace(returncode=0))
    assert c.main(['upgrade','--core-rpm','signed.rpm']) == 21
    assert not invoked

@pytest.mark.parametrize('field,value',[('version','3.2.180'),('source_revision','f'*40),
    ('core_nevra','endpoint-agent-3.2.179-alt7.x86_64'),('core_rpm_sha256','e'*64)])
def test_executor_binding_also_binds_source_record_to_verified_core(field,value):
    from pc_agent.platform.linux.installation_coordinator import assert_executor_binding
    native = proof()
    with pytest.raises(InstallationPending):
        assert_executor_binding(binding(native) | {field:value},native,
            {'sha256':'d'*64,'source_revision':'a'*40,'version':'3.2.179'})

@pytest.mark.parametrize('version',['3.2.179','3.2.178'])
def test_retained_executor_accepts_only_current_frozen_setup_identity(tmp_path,monkeypatch,version):
    from contextlib import contextmanager, nullcontext
    from types import SimpleNamespace
    from pc_agent.platform.linux import installation_coordinator as c, native_build_identity as identity
    from pc_agent.tests.test_linux_installation_lifecycle import MemoryStore
    store = MemoryStore()
    store.paths = SimpleNamespace(private=tmp_path)
    store.locked = nullcontext
    executable = tmp_path/('setup-'+'d'*64)
    monkeypatch.setattr(c.sys,'frozen',True,raising=False)
    monkeypatch.setattr(c.sys,'executable',str(executable))
    @contextmanager
    def snapshot(_): yield executable,'d'*64
    monkeypatch.setattr(c,'snapshot',snapshot)
    monkeypatch.setattr(identity,'build_identity',lambda:{'component':'setup','version':version,'source_revision':'a'*40})
    if version == '3.2.179':
        c.retain_executor(store)
        assert store.json('executor.json') == {'path':str(executable),'sha256':'d'*64,'source_revision':'a'*40,'version':'3.2.179'}
    else:
        with pytest.raises(InstallationPending): c.retain_executor(store)
        assert store.json('executor.json',missing=True) is None
