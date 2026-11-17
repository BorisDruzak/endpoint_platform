"""Explicit existing local/domain administrator binding for Windows OpenSSH."""
from types import SimpleNamespace
import sys
import pytest
from pc_agent.platform.windows import support_access_native as native,support_access as support

@pytest.fixture
def account(monkeypatch):
    calls=[];state={'kind':1,'domain':'CONTOSO','name':'Operator','sid':'S-1-5-21-1-2-3-1001','status_sid':'S-1-5-21-1-2-3-1001','flags':512,'groups':['Localized admins'],'unavailable':False}
    def lookup(server,name):
        calls.append(('lookup',server,name))
        if state['unavailable']:raise OSError('DC unavailable')
        return state['sid'],state['domain'],state['kind']
    def reverse(server,sid):return state['name'],state['domain'],state['kind']
    def info(server,name,level):
        calls.append(('info',server,name,level))
        assert level==4
        return {'name':state['name'],'flags':state['flags'],'user_sid':state['status_sid']}
    def groups(server,name,flags):
        calls.append(('groups',server,name,flags));assert server is None and flags==1
        return state['groups']
    def dc(server,domain):calls.append(('dc',server,domain));return r'\\DC1'
    monkeypatch.setitem(sys.modules,'win32security',SimpleNamespace(LookupAccountName=lookup,LookupAccountSid=reverse,SidTypeUser=1,ConvertSidToStringSid=lambda sid:sid))
    monkeypatch.setitem(sys.modules,'win32api',SimpleNamespace(GetComputerName=lambda:'WORKSTATION'))
    monkeypatch.setitem(sys.modules,'win32net',SimpleNamespace(NetUserGetInfo=info,NetUserGetLocalGroups=groups,NetGetDCName=dc))
    monkeypatch.setattr(native,'administrators_name',lambda:'Localized admins')
    return state,calls


def test_explicit_domain_account_is_bound_to_sid_status_and_local_indirect_admin(account):
    state,calls=account
    assert native.validate_windows_admin(r'CONTOSO\Operator')==r'contoso\operator'
    assert ('dc',None,'CONTOSO') in calls
    assert ('info',r'\\DC1','Operator',4) in calls
    assert ('groups',None,r'CONTOSO\Operator',1) in calls


@pytest.mark.parametrize('qualified',[False,True])
def test_local_account_uses_explicit_local_resolution_and_local_status(account,qualified):
    state,calls=account;state.update(domain='WORKSTATION',name='LocalAdmin')
    assert native.validate_windows_admin(r'WORKSTATION\LocalAdmin' if qualified else 'LocalAdmin')=='localadmin'
    assert ('lookup',None,r'WORKSTATION\LocalAdmin') in calls
    assert ('info',None,'LocalAdmin',4) in calls
    assert not any(call[0]=='dc' for call in calls)


@pytest.mark.parametrize('defect',['nonuser','wrong-domain','wrong-name','disabled','not-admin','status-sid','network','bare-domain'])
def test_identity_or_status_ambiguity_fails_closed(account,defect):
    state,calls=account;principal=r'CONTOSO\Operator'
    if defect=='nonuser':state['kind']=3
    if defect=='wrong-domain':state['domain']='OTHER'
    if defect=='wrong-name':state['name']='Other'
    if defect=='disabled':state['flags']|=2
    if defect=='not-admin':state['groups']=['Users']
    if defect=='status-sid':state['status_sid']='S-1-5-21-9-8-7-1001'
    if defect=='network':state['unavailable']=True
    if defect=='bare-domain':principal='Operator'
    with pytest.raises(ValueError,match='support_existing_admin_required'):native.validate_windows_admin(principal)


@pytest.mark.parametrize('name',[r'CONTOSO\Operator','LocalAdmin'])
def test_sshd_allowusers_is_lowercase_and_keeps_exact_sam_separator(tmp_path,name):
    p=SimpleNamespace(local_port=22222,windows_admin_username=name)
    config=support.sshd_config(tmp_path,p)
    assert 'AllowUsers '+name.lower()+'\n' in config


@pytest.mark.parametrize('name',['user@domain','DOMAIN/user',r'DOMAIN\user\other','DOMAIN\\user\nMatch all','DOMAIN\\*'])
def test_sshd_render_rejects_configuration_patterns(tmp_path,name):
    p=SimpleNamespace(local_port=22222,windows_admin_username=name)
    with pytest.raises(ValueError):support.sshd_config(tmp_path,p)


def test_domain_capability_has_distinct_component_version():
    assert tuple(int(p) for p in support.COMPONENT_VERSION.split('.'))>=(1,0,1)


@pytest.mark.parametrize('name',[r'CONTOSO\Operator','D'*16+'\\user','D'*15+'\\'+'u'*49,'user@domain','DOMAIN\\user\nMatch all'])
def test_policy_parser_domain_principal_boundaries(name):
    from datetime import datetime,timezone
    from pc_agent.tests.windows.test_support_access import policy,DEVICE
    now=datetime.now(timezone.utc);raw=policy(now);raw['windows_admin_username']=name
    if name==r'CONTOSO\Operator':
        assert support.SupportPolicy.parse(raw,device_id=DEVICE,now=now).windows_admin_username==r'contoso\operator'
    else:
        with pytest.raises(ValueError):support.SupportPolicy.parse(raw,device_id=DEVICE,now=now)


@pytest.mark.parametrize('local',[False,True])
def test_runtime_uses_validated_canonical_account_in_private_sshd_config(account,monkeypatch,tmp_path,local):
    from datetime import datetime,timezone
    from pc_agent.tests.windows.test_support_access import policy,DEVICE
    state,calls=account
    if local:state.update(domain='WORKSTATION',name='LocalAdmin')
    now=datetime.now(timezone.utc);raw=policy(now)
    raw['windows_admin_username']=r'WORKSTATION\LocalAdmin' if local else r'CONTOSO\Operator'
    configured=support.SupportPolicy.parse(raw,device_id=DEVICE,now=now)
    monkeypatch.setattr(native,'verify_dependencies',lambda _:None)
    monkeypatch.setattr(native,'assert_private',lambda _:None)
    monkeypatch.setattr(native.WindowsSupportOps,'protect',lambda *args:None)
    monkeypatch.setattr(native.subprocess,'run',lambda *args,**kwargs:SimpleNamespace(returncode=0))
    class Job:
        def launch(self,*args,**kwargs):pass
        def close(self):pass
    monkeypatch.setattr(native,'NativeProcessJob',Job)
    children=native.SupportChildren(tmp_path,{'ssh':'ssh.exe','sshd':'sshd.exe'})
    try:
        children.start(configured)
        expected='localadmin' if local else r'contoso\operator'
        assert 'AllowUsers '+expected+'\n' in (tmp_path/'sshd_config').read_text()
    finally:children.stop()



def test_actual_service_loop_attests_its_compiled_version_on_status():
    from datetime import datetime,timezone
    from threading import Event
    from pc_agent.platform.windows import support_access_service as service
    from pc_agent.tests.windows.test_support_access import policy,DEVICE,Children
    stop=Event();calls=[];raw=policy(datetime.now(timezone.utc));raw['enabled']=False
    class Client(support.SupportHTTPClient):
        def __init__(self):pass
        def policy(self):return raw
        def request(self,operation,body=None):
            calls.append((operation,body));stop.set();return raw
    service.run_supervisor(DEVICE,Client(),Children(),stop)
    assert calls==[('status',{'installed':True,'tunnel_connected':False,'last_error_code':None,
                              'component_version':support.COMPONENT_VERSION})]
