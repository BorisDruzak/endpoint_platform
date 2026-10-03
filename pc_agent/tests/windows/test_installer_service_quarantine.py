"""Own installer lifecycle models; these tests never open real SCM services."""
from types import SimpleNamespace
import pytest
from pc_agent.platform.windows import installer_transaction_bridge as bridge


class Services:
    def __init__(self, root):
        self.calls=[]; self.fail=None
        self.values={
            'EndpointAgent':[16,2,1,f'"{root / "endpoint-agent-service.exe"}" --agent-service','',0,[],r'NT AUTHORITY\LocalService','Agent'],
            'EndpointAgentUpdater':[16,3,1,f'"{root / "endpoint-agent-updater.exe"}" --updater-service','',0,[],'LocalSystem','Updater']}
        self.delayed={'EndpointAgent':True,'EndpointAgentUpdater':False}
        self.status={name:1 for name in self.values}
    def OpenSCManager(self,*args): return 'scm'
    def OpenService(self,scm,name,access):
        assert name in self.values
        if self.values[name] is None:
            error=OSError('absent');error.winerror=1060;raise error
        return name
    def CloseServiceHandle(self,*args): pass
    def QueryServiceConfig(self,name): return tuple(self.values[name])
    def QueryServiceConfig2(self,name,level): assert level==3;return self.delayed[name]
    def QueryServiceStatus(self,name): return (16,self.status[name],0,0,0,0,0)
    def ChangeServiceConfig(self,name,kind,start,error,*rest):
        assert kind==error==0xffffffff and rest==(None,None,0,None,None,None,None)
        self.calls.append((name,start))
        if name==self.fail: raise OSError('configuration failed')
        self.values[name][1]=start
    def ChangeServiceConfig2(self,name,level,value):
        assert level==3;self.calls.append((name,'delayed',value));self.delayed[name]=value


def test_exact_snapshot_precedes_disable_and_final_enable_is_idempotent(tmp_path):
    api=Services(tmp_path);paths=SimpleNamespace(install_root=tmp_path);events=[]
    with bridge.InstallerServices(paths,api=api,checkpoint=lambda:events.append('owner'),flush=lambda name:events.append(('flush',name))) as services:
        snapshot=services.snapshot()
        assert snapshot=={'EndpointAgent':{'start_type':2,'delayed_auto':True},'EndpointAgentUpdater':{'start_type':3,'delayed_auto':False}}
        assert api.calls==[]
        services.quarantine(snapshot)
        assert [v[1] for v in api.values.values()]==[4,4]
        services.restore_final()
        assert [v[1] for v in api.values.values()]==[2,3]
        assert api.delayed=={'EndpointAgent':False,'EndpointAgentUpdater':False}
        count=len(api.calls);events.clear();services.restore_final();assert len(api.calls)==count
        assert events==['owner',('flush','EndpointAgent'),'owner',('flush','EndpointAgentUpdater')]
        assert events


@pytest.mark.parametrize('defect',['running','wrong_image','wrong_account','partial_failure','owner_lost'])
def test_quarantine_never_starts_or_stops_a_service_and_preserves_partial_failure(tmp_path,defect):
    api=Services(tmp_path);paths=SimpleNamespace(install_root=tmp_path)
    def checkpoint():
        if defect=='owner_lost': raise ValueError('OWNER_AUTH_FAILED')
    if defect=='running': api.status['EndpointAgentUpdater']=4
    if defect=='wrong_image': api.values['EndpointAgent'][3]='other.exe'
    if defect=='wrong_account': api.values['EndpointAgent'][7]='OtherUser'
    if defect=='partial_failure': api.fail='EndpointAgentUpdater'
    with pytest.raises((ValueError,OSError)):
        with bridge.InstallerServices(paths,api=api,checkpoint=checkpoint,flush=lambda _:None) as services:
            services.quarantine(services.snapshot())
    if defect=='partial_failure': assert api.values['EndpointAgent'][1]==4
    else: assert api.calls==[]


def test_original_delayed_snapshot_survives_recovery_and_restores_exactly(tmp_path):
    api=Services(tmp_path)
    with bridge.InstallerServices(SimpleNamespace(install_root=tmp_path),api=api,flush=lambda _:None) as services:
        original=services.snapshot();services.quarantine(original)
        services.quarantine(original,recovery=True)
        assert original['EndpointAgent']=={'start_type':2,'delayed_auto':True}
        services.restore_original(original)
        assert services.snapshot()==original


def test_absent_services_remain_absent_during_quarantine(tmp_path):
    api=Services(tmp_path);api.values={name:None for name in api.values}
    with bridge.InstallerServices(SimpleNamespace(install_root=tmp_path),api=api,flush=lambda _:pytest.fail('absent key flush')) as services:
        original=services.snapshot();services.quarantine(original);services.restore_original(original)
        assert not api.calls
        with pytest.raises(ValueError): services.restore_final()


def test_flush_failure_stops_before_second_service(tmp_path):
    api=Services(tmp_path)
    def failed(name):
        assert name=='EndpointAgent' and api.values[name][1]==4
        raise OSError('flush failed')
    with bridge.InstallerServices(SimpleNamespace(install_root=tmp_path),api=api,flush=failed) as services:
        with pytest.raises(OSError,match='flush failed'): services.quarantine(services.snapshot())
    assert api.values['EndpointAgentUpdater'][1]==3


def test_flush_opens_only_fixed_service_key_with_query_access(monkeypatch):
    import winreg
    events=[]
    class Key:
        def __enter__(self): return self
        def __exit__(self,*args): events.append('close')
    def opened(root,path,reserved,access):
        assert root==winreg.HKEY_LOCAL_MACHINE and reserved==0
        assert access==winreg.KEY_QUERY_VALUE|winreg.KEY_WOW64_64KEY
        events.append(path);return Key()
    monkeypatch.setattr(winreg,'OpenKey',opened)
    monkeypatch.setattr(winreg,'FlushKey',lambda key:events.append('flush'))
    bridge.InstallerServices._flush_service('EndpointAgent')
    assert events==[r'SYSTEM\CurrentControlSet\Services\EndpointAgent','flush','close']
    with pytest.raises(ValueError): bridge.InstallerServices._flush_service('Other')
