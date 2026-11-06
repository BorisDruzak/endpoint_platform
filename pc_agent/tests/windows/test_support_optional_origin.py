"""Standalone Support accepts only the proven absence of optional origin."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from pc_agent.tests.windows.test_installer_fence import native_protected_root

DEVICE='11111111-2222-4333-8444-555555555555'

@pytest.fixture
def enrolled(native_protected_root,monkeypatch):
    from pc_agent.platform.windows import support_access_service as service,installer_fence as fence
    root=native_protected_root/'data/Support';program=native_protected_root/'program/Support';agent=root.parent/'Agent';agent.mkdir(parents=True)
    values={'device-credential':'c'*43,'endpoint-ca.crt':'CA-COPY','enrollment-identity.json':json.dumps({'schema_version':'endpoint_enrollment_identity_v1','device_id':DEVICE})}
    for name,value in values.items():
        path=agent/name;path.write_text(value);fence.protect_state(path,secret=True)
    monkeypatch.setattr(service,'production_roots',lambda:(root,program))
    calls=[];monkeypatch.setattr(service,'install_support_access',lambda *args,**kw:calls.append(kw) or {'installed':True})
    return service,agent,calls


@pytest.mark.parametrize('origin',[None,'https://alternate.sosnadmin.local'])
def test_optional_origin_matches_canonical_default_without_mutating_agent(enrolled,origin):
    from pc_agent.platform.windows import installer_fence as fence,service_launcher
    service,agent,calls=enrolled
    if origin is not None:
        path=agent/'endpoint-origin';path.write_text(origin);fence.protect_state(path,secret=True)
    before={p.name:p.read_bytes() for p in agent.iterdir()}
    assert service.install_from_enrollment()['installed']
    assert calls[0]['origin']==(origin or service_launcher._DEFAULT_ENDPOINT_ORIGIN)
    assert {p.name:p.read_bytes() for p in agent.iterdir()}==before


@pytest.mark.parametrize('name',['device-credential','endpoint-ca.crt','enrollment-identity.json'])
def test_other_enrollment_inputs_remain_required(enrolled,name):
    service,agent,calls=enrolled;(agent/name).unlink()
    with pytest.raises((ValueError,FileNotFoundError)):service.install_from_enrollment()
    assert not calls


@pytest.mark.parametrize('kind',['http','unreadable','dangling','unsafe-acl','directory'])
def test_existing_origin_failure_never_falls_back(enrolled,monkeypatch,kind):
    from pc_agent.platform.windows import installer_fence as fence
    service,agent,calls=enrolled;path=agent/'endpoint-origin'
    if kind=='directory':path.mkdir()
    elif kind=='dangling':path.symlink_to(agent/'missing-target')
    else:
        path.write_text('http://endpoint.sosnadmin.local' if kind=='http' else 'https://alternate.sosnadmin.local')
        fence.protect_state(path,secret=True)
    if kind=='unreadable':
        original=Path.read_text
        def read(p,*args,**kw):
            if p==path:raise PermissionError('not readable')
            return original(p,*args,**kw)
        monkeypatch.setattr(Path,'read_text',read)
    if kind=='unsafe-acl':
        import win32security as s
        descriptor=s.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;FA;;;WD)',1)
        s.SetNamedSecurityInfo(str(path),s.SE_FILE_OBJECT,s.DACL_SECURITY_INFORMATION|s.PROTECTED_DACL_SECURITY_INFORMATION,None,None,descriptor.GetSecurityDescriptorDacl(),None)
    with pytest.raises((ValueError,OSError)):service.install_from_enrollment()
    assert not calls


@pytest.mark.parametrize('code',['support_dependency_reboot_required','private token ccccccccccccccccccccccccccccccccccccccccccc'])
def test_staged_helper_failure_is_bounded_and_preserved(monkeypatch,tmp_path,code):
    from pc_agent.platform.windows import provision,update_paths
    monkeypatch.setattr(update_paths,'_native_folder',lambda folder:tmp_path/('data' if folder==0x23 else 'program'))
    data=tmp_path/'data/Endpoint Platform/Agent';exe=tmp_path/'program/Endpoint Platform/Agent/EndpointSupportAccess.exe';exe.parent.mkdir(parents=True);exe.write_bytes(b'staged')
    monkeypatch.setattr(__import__('subprocess'),'run',lambda *args,**kw:SimpleNamespace(returncode=1,stdout=json.dumps({'installed':False,'error':code}),stderr='ignored secret'))
    result=provision.install_enrolled_support(data)
    assert result=={'installed':False,'error':code if code.startswith('support_dependency_') else 'support_install_failed'}


def test_setup_result_retains_safe_code_and_drops_untrusted_text(monkeypatch,tmp_path):
    from pc_agent.platform.windows import setup_entry as setup,provision
    monkeypatch.setattr(setup,'_prepare_diagnostics_root',lambda:tmp_path)
    for code in ('support_dependency_reboot_required','secret bearer token'):
        monkeypatch.setattr(provision,'install_enrolled_support',lambda _,code=code:{'installed':False,'error':code})
        setup._install_support_after_native(tmp_path)
        result=json.loads((tmp_path/'support-install-result.json').read_text())
        assert result['error_code']==(code if code.startswith('support_dependency_') else 'support_install_failed')


def test_missing_origin_parent_is_not_optional(tmp_path):
    from pc_agent.platform.windows import support_access_service as service
    with pytest.raises(FileNotFoundError):service._enrollment_origin(tmp_path/'missing-agent')


def test_fresh_provisioning_preserves_safe_error_without_replaying_enrollment(tmp_path):
    import io
    from pc_agent.platform.windows.provision import WindowsProvisioner
    from pc_agent.tests.windows.test_provisioning_contract import _request,_Enrollment,_Service,_Acl,_CLAIM
    events=[];request=_request(tmp_path)
    result=WindowsProvisioner(request,enrollment=_Enrollment(events),service=_Service(events),acl=_Acl(events),
        support_installer=lambda:{'installed':False,'error':'support_dependency_reboot_required'}).provision_from_stdin(io.StringIO(_CLAIM))
    assert result.support_access_status=='unavailable'
    assert result.support_access_error=='support_dependency_reboot_required'
    assert result.claim_removed and events.count('gateway.enroll')==events.count('service.start')==1


def test_setup_preserves_fresh_provisioner_safe_error(monkeypatch,tmp_path):
    from pc_agent.platform.windows import setup_entry as setup
    monkeypatch.setattr(setup,'_prepare_diagnostics_root',lambda:tmp_path)
    config=setup.SetupConfig(endpoint_origin='https://endpoint.sosnadmin.local',ca_file=tmp_path/'ca.pem',installer_version='3.2.175',installer_release_id='3.2.175')
    value={'support_access_status':'unavailable','support_access_error':'support_dependency_reboot_required'}
    setup._run_provisioner(tmp_path/'provision.exe',config,tmp_path/'data','machine','claim',
        run=lambda *args,**kwargs:SimpleNamespace(returncode=0,stdout=json.dumps(value),stderr='ignored secret'))
    assert json.loads((tmp_path/'support-install-result.json').read_text())['error_code']=='support_dependency_reboot_required'
