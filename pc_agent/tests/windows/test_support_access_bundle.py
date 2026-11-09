"""Closed, pinned private runtime; never service/OS capability mutation."""
import copy,hashlib,importlib,json,os,stat,zipfile
from pathlib import Path
import pytest
from pc_agent.tests.windows.test_installer_fence import native_protected_root

ARCHIVE_ENV='ENDPOINT_TEST_OPENSSH_ZIP'


def bundle():return importlib.import_module('pc_agent.platform.windows.support_access_bundle')


@pytest.fixture
def archive(tmp_path):
    files={'ssh.exe':b'ssh','sshd.exe':b'sshd','ssh-keygen.exe':b'keygen','libcrypto.dll':b'crypto','LICENSE.txt':b'license','NOTICE.txt':b'notice','moduli':b'moduli'}
    path=tmp_path/'bundle.zip'
    with zipfile.ZipFile(path,'w') as z:
        for name,value in files.items():z.writestr('OpenSSH-Win64/'+name,value)
    rows=[{'path':name,'size':len(value),'sha256':hashlib.sha256(value).hexdigest()} for name,value in files.items()]
    manifest={'schema_version':1,'version':'test','archive_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'archive_size':path.stat().st_size,'runtime_files':rows,
        'archive_members':[{**row,'path':'OpenSSH-Win64/'+row['path']} for row in rows]}
    return path,manifest,files


def test_public_manifest_pins_complete_microsoft_closure():
    m=bundle().load_manifest()
    assert m['preview'] is True and len([r for r in m['runtime_files'] if r['path'].endswith(('.exe','.dll'))])==15
    assert {'sshd-auth.exe','sshd-session.exe','ssh-shellhost.exe','libcrypto.dll','LICENSE.txt','NOTICE.txt','moduli'}<={r['path'] for r in m['runtime_files']}


def test_closed_archive_matches_before_any_publish(archive):
    path,m,files=archive
    bundle().validate_archive(path,m)


@pytest.mark.parametrize('attack',['traversal','absolute','case-alias','duplicate','symlink','extra','missing'])
def test_closed_archive_rejects_malicious_members(archive,tmp_path,attack):
    path,m,files=archive;evil=tmp_path/'evil.zip'
    with zipfile.ZipFile(evil,'w') as z:
        for name,value in files.items():
            if attack=='missing' and name=='ssh.exe':continue
            info=zipfile.ZipInfo('OpenSSH-Win64/'+name)
            if attack=='symlink' and name=='ssh.exe':info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16
            z.writestr(info,value)
        extra={'traversal':'OpenSSH-Win64/../outside','absolute':'/outside','case-alias':'OpenSSH-Win64/SSH.exe','duplicate':'OpenSSH-Win64/ssh.exe','extra':'OpenSSH-Win64/foreign.exe'}.get(attack)
        if extra:z.writestr(extra,b'bad')
    m=copy.deepcopy(m);m.update(archive_sha256=hashlib.sha256(evil.read_bytes()).hexdigest(),archive_size=evil.stat().st_size)
    with pytest.raises(ValueError):bundle().validate_archive(evil,m)


@pytest.mark.parametrize('existing',[False,True])
def test_valid_os_profile_is_preferred_without_bundle_or_mutation(monkeypatch,existing):
    from pc_agent.platform.windows import support_access_native as native
    from pc_agent.platform.windows import support_access_os as os_runtime
    from pc_agent.tests.windows.test_support_access_os import Servicing,CLIENT,SERVER
    profile={'profile':os_runtime.PROFILE,'keygen':'verified-os-keygen'}
    adapter=Servicing({CLIENT:'Installed',SERVER:'Installed'})
    adapter.verify=lambda:profile
    monkeypatch.setattr(os_runtime,'WindowsFOD',lambda root:adapter)
    monkeypatch.setattr(bundle(),'install',lambda:pytest.fail('valid OS must not install bundle'))
    ops=native.WindowsSupportOps()
    assert ops.dependencies(existing=existing)==profile and ops._keygen=='verified-os-keygen'


def test_missing_os_uses_only_fixed_fod_preparation_not_preview(monkeypatch):
    from pc_agent.platform.windows import support_access_native as native
    from pc_agent.platform.windows import support_access_os as os_runtime
    from pc_agent.tests.windows.test_support_access_os import Servicing,CLIENT,SERVER
    profile={'profile':os_runtime.PROFILE,'keygen':'verified-os-keygen'}
    adapter=Servicing({CLIENT:'Installed',SERVER:'NotPresent'})
    adapter.verify=lambda:profile
    monkeypatch.setattr(os_runtime,'WindowsFOD',lambda root:adapter)
    monkeypatch.setattr(bundle(),'install',lambda:pytest.fail('new media must not select Preview'))
    ops=native.WindowsSupportOps();assert ops.dependencies()==profile
    assert ops._keygen=='verified-os-keygen'
    assert ('install',(SERVER,)) in adapter.events


def test_existing_exact_bundle_is_verified_and_retained_before_os_migration(monkeypatch):
    from pc_agent.platform.windows import support_access_native as native
    from pc_agent.platform.windows import support_access_os as os_runtime
    from pc_agent.tests.windows.test_support_access_os import Servicing,CLIENT,SERVER
    profile={'profile':bundle().PROFILE,'keygen':'existing-bundle-keygen'}
    replacement={'profile':os_runtime.PROFILE,'keygen':'verified-os-keygen'}
    calls=[]
    monkeypatch.setattr(bundle(),'verify_profile',lambda p:calls.append(p) or p)
    adapter=Servicing({CLIENT:'Installed',SERVER:'Installed'})
    adapter.verify=lambda:replacement
    monkeypatch.setattr(os_runtime,'WindowsFOD',lambda root:adapter)
    monkeypatch.setattr(bundle(),'remove',lambda:pytest.fail('retain old compensation bytes'))
    assert native.WindowsSupportOps().dependencies(previous=profile,existing=True)==replacement
    assert calls==[profile]


def test_incompatible_migration_precedes_keys_registration_config_and_stop(monkeypatch,tmp_path):
    from pc_agent.platform.windows import support_access as support,support_access_native as native
    from pc_agent.tests.windows.test_support_access import _PayloadTestOps,DEVICE
    class Ops(_PayloadTestOps,native.WindowsSupportOps):
        def protect(self,p):
            if not p.exists():p.mkdir(parents=True)
        def dependencies(self,**kwargs):raise ValueError('support_dependency_migration_unsupported')
        def key(self,*args):pytest.fail('keys must remain untouched')
        def stop_for_update(self,*args):pytest.fail('service must remain untouched')
    monkeypatch.setattr(bundle(),'install',lambda:pytest.fail('incompatible old payload must not publish bundle'))
    data=tmp_path/'data/Agent';root=data.parent/'Support';root.mkdir(parents=True)
    config=root/'support.json';config.write_text(json.dumps({'device_id':DEVICE,'origin':'https://endpoint.sosnadmin.local','dependencies':{'keygen':'old'}}))
    (root/'credential').write_text('unchanged');(root/'host_ed25519').write_bytes(b'unchanged key')
    program=tmp_path/'program/Support';program.mkdir(parents=True);target=program/'EndpointSupportAccess.exe';target.write_bytes(b'old image')
    source=tmp_path/'offer.exe';source.write_bytes(b'new image');before={p.name:p.read_bytes() for p in root.iterdir()}
    with pytest.raises(ValueError,match='migration_unsupported'):
        support.install_support_access(data,program.parent/'Agent',origin='https://endpoint.sosnadmin.local',ca_pem='newCA',device_id=DEVICE,device_token='x'*43,service_executable=source,_ops=Ops(),_client=object())
    assert {p.name:p.read_bytes() for p in root.iterdir()}==before and target.read_bytes()==b'old image'


@pytest.fixture
def published(archive,native_protected_root,monkeypatch):
    path,m,_=archive;module=bundle()
    monkeypatch.setattr(module,'runtime_root',lambda:native_protected_root/'SupportRuntime')
    monkeypatch.setattr(module,'resources',lambda:path.parent)
    monkeypatch.setattr(module,'load_manifest',lambda:m)
    monkeypatch.setattr(module,'verify_signatures',lambda *args:None)
    path.rename(path.parent/'OpenSSH-Win64.zip')
    return module,module.install(),m


def test_publish_acl_profile_and_owned_removal_are_real(published):
    module,profile,m=published
    assert module.verify_profile(profile)==profile
    root=module.runtime_root();module.assert_public(root)
    assert (root/module.slot_name(m)/'LICENSE.txt').read_bytes()==b'license'
    module.remove();assert not root.exists()


@pytest.mark.parametrize('defect',['path','hash','extra','acl'])
def test_published_bundle_rejects_tampering_and_preserves_foreign_state(published,defect):
    module,profile,m=published;root=module.runtime_root();slot=root/module.slot_name(m)
    if defect=='path':profile['ssh']=str(root/'outside.exe')
    if defect=='hash':(slot/'ssh.exe').write_bytes(b'wrong')
    if defect=='extra':(slot/'foreign').write_bytes(b'preserve me')
    if defect=='acl':
        import win32security as s
        d=s.ConvertStringSecurityDescriptorToSecurityDescriptor('D:P(A;;FA;;;WD)',1)
        s.SetNamedSecurityInfo(str(slot/'ssh.exe'),s.SE_FILE_OBJECT,s.DACL_SECURITY_INFORMATION|s.PROTECTED_DACL_SECURITY_INFORMATION,None,None,d.GetSecurityDescriptorDacl(),None)
    with pytest.raises(ValueError):module.verify_profile(profile)
    if defect!='path':
        with pytest.raises(ValueError):module.remove()
        assert (slot/'ssh.exe').exists()


def test_build_requires_explicit_pinned_archive(monkeypatch):
    from tools.canary.support_openssh_payload import resource_datas
    monkeypatch.delenv('ENDPOINT_SUPPORT_OPENSSH_ZIP',raising=False)
    with pytest.raises(ValueError,match='explicit'):resource_datas(Path(__file__).resolve().parents[3])


def test_actual_official_archive_signatures_and_private_publish(native_protected_root,monkeypatch):
    value=os.environ.get(ARCHIVE_ENV)
    if not value:pytest.skip('opt-in exact external Microsoft ZIP')
    module=bundle();m=module.load_manifest();path=Path(value)
    module.validate_archive(path,m)
    monkeypatch.setattr(module,'load_manifest',lambda:m)
    monkeypatch.setattr(module,'resources',lambda:path.parent)
    monkeypatch.setattr(module,'runtime_root',lambda:native_protected_root/'SupportRuntime')
    profile=module.install();assert module.verify_profile(profile)==profile
    assert len(list((module.runtime_root()/module.slot_name(m)).glob('*.exe')))==14
    module.remove()



def test_signature_failure_leaves_private_owned_stage_and_uninstall_removes_it(archive,native_protected_root,monkeypatch):
    path,m,_=archive;module=bundle();path.rename(path.parent/'OpenSSH-Win64.zip')
    monkeypatch.setattr(module,'runtime_root',lambda:native_protected_root/'SupportRuntime')
    monkeypatch.setattr(module,'resources',lambda:path.parent)
    monkeypatch.setattr(module,'load_manifest',lambda:m)
    monkeypatch.setattr(module,'verify_signatures',lambda *args:(_ for _ in ()).throw(ValueError('signature invalid')))
    with pytest.raises(ValueError):module.install()
    from pc_agent.platform.windows.support_access_native import assert_private
    root=module.runtime_root();assert_private(root)
    assert not (root/module.slot_name(m)).exists()
    module.remove();assert not root.exists()


def test_build_pins_real_zip_and_vendor_notices(monkeypatch):
    value=os.environ.get(ARCHIVE_ENV)
    if not value:pytest.skip('opt-in exact external Microsoft ZIP')
    from tools.canary.support_openssh_payload import resource_datas
    monkeypatch.setenv('ENDPOINT_SUPPORT_OPENSSH_ZIP',value)
    result=resource_datas(Path(__file__).resolve().parents[3])
    assert len(result)==5 and result[0]==(str(Path(value).resolve()),'support-openssh')



def test_verified_real_runtime_static_version_and_own_config_only(native_protected_root,monkeypatch):
    value=os.environ.get(ARCHIVE_ENV)
    if not value:pytest.skip('opt-in exact external Microsoft ZIP')
    import subprocess
    from types import SimpleNamespace
    from pc_agent.platform.windows import support_access_native as native,support_access as support
    module=bundle();manifest=module.load_manifest();path=Path(value)
    monkeypatch.setattr(module,'load_manifest',lambda:manifest)
    monkeypatch.setattr(module,'resources',lambda:path.parent)
    monkeypatch.setattr(module,'runtime_root',lambda:native_protected_root/'SupportRuntime')
    profile=module.install() # All15 Microsoft signatures verified before execution.
    root=native_protected_root/'private';ops=native.WindowsSupportOps();ops.protect(root)
    ops.key(root,'host_ed25519') # Existing signed OS client keygen; own scratch key.
    config=root/'sshd_config'
    config.write_text(support.sshd_config(root,SimpleNamespace(local_port=22222,windows_admin_username='test_user'))+
        'ModuliFile '+support._ssh_path(Path(profile['sshd']).parent/'moduli')+'\n')
    ops.protect(config)
    version=subprocess.run([profile['ssh'],'-V'],capture_output=True,text=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    assert version.returncode==0 and '10.4' in version.stderr+version.stdout
    checked=subprocess.run([profile['sshd'],'-D','-e','-t','-f',str(config)],capture_output=True,text=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    assert checked.returncode==0,checked.stderr
    module.remove()


def test_os_signature_query_is_read_only_and_uses_system_modules(monkeypatch,tmp_path):
    import base64,subprocess
    from pc_agent.platform.windows import support_access_native as native
    windows=tmp_path/'Windows';directory=windows/'System32/OpenSSH';directory.mkdir(parents=True)
    for name in ('ssh.exe','sshd.exe','ssh-keygen.exe'):(directory/name).write_bytes(b'OS fixture')
    monkeypatch.setattr(native,'windows_root',lambda:windows)
    monkeypatch.setattr(native,'verify_dependencies',lambda _:None)
    original=subprocess.run
    prefix=r'''
function Get-WindowsCapability {throw 'forbidden capability query'}
function Add-WindowsCapability {throw 'forbidden servicing'}
function Set-Service {throw 'forbidden global service change'}
function New-NetFirewallRule {throw 'forbidden firewall change'}
function Get-AuthenticodeSignature {param($LiteralPath) @{Status='Valid';SignerCertificate=@{Subject='O=Microsoft Corporation'}}}
function Get-Item {param($LiteralPath) @{VersionInfo=@{FileVersion='9.5.6.4'}}}
function Get-FileHash {param($LiteralPath,$Algorithm) @{Hash=('a'*64)}}
'''
    def run(args,**kwargs):
        script=base64.b64decode(args[-1]).decode('utf-16-le')
        assert kwargs['env']['PSModulePath']==str(windows/'System32/WindowsPowerShell/v1.0/Modules')
        # Keep genuine OS PowerShell/module paths for this controlled command test.
        kwargs.pop('env');encoded=base64.b64encode((prefix+script).encode('utf-16-le')).decode()
        return original(['powershell.exe',*args[1:-1],encoded],**kwargs)
    monkeypatch.setattr(native.subprocess,'run',run)
    result=native.WindowsSupportOps().os_dependencies()
    assert result['automatic_inbound_rule_removed'] is False
    assert result['versions']['sshd']=='9.5.6.4'



def test_interrupted_public_acl_publication_retains_owned_cleanup(archive,native_protected_root,monkeypatch):
    path,m,_=archive;module=bundle();path.rename(path.parent/'OpenSSH-Win64.zip')
    monkeypatch.setattr(module,'runtime_root',lambda:native_protected_root/'SupportRuntime')
    monkeypatch.setattr(module,'resources',lambda:path.parent);monkeypatch.setattr(module,'load_manifest',lambda:m)
    monkeypatch.setattr(module,'verify_signatures',lambda *args:None)
    original=module._public;count=[0]
    def publish(p):
        count[0]+=1
        if count[0]==2:raise PermissionError('interrupted ACL publication')
        original(p)
    monkeypatch.setattr(module,'_public',publish)
    with pytest.raises(PermissionError):module.install()
    module.remove();assert not module.runtime_root().exists()



def test_interrupted_uninstall_keeps_marker_and_can_retry(published,monkeypatch):
    module,profile,m=published;slot=module.runtime_root()/module.slot_name(m);original=Path.unlink;failed=[False]
    def unlink(path,*args,**kwargs):
        if path==slot/'sshd.exe' and not failed[0]:failed[0]=True;raise PermissionError('file busy')
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'unlink',unlink)
    with pytest.raises(PermissionError):module.remove()
    assert (slot/module.MARKER).is_file()
    module.remove();assert not module.runtime_root().exists()


def test_empty_exact_slot_after_marker_removal_is_retryable(published,monkeypatch):
    module,profile,m=published;slot=module.runtime_root()/module.slot_name(m);original=Path.rmdir;failed=[False]
    def rmdir(path):
        if path==slot and not failed[0]:failed[0]=True;raise PermissionError('directory busy')
        return original(path)
    monkeypatch.setattr(Path,'rmdir',rmdir)
    with pytest.raises(PermissionError):module.remove()
    assert not list(slot.iterdir())
    module.remove();assert not module.runtime_root().exists()



def test_cleanup_refuses_dangling_runtime_root(native_protected_root,monkeypatch):
    module=bundle();root=native_protected_root/'SupportRuntime';root.symlink_to(native_protected_root/'foreign-missing',target_is_directory=True)
    monkeypatch.setattr(module,'runtime_root',lambda:root)
    with pytest.raises(ValueError):module.remove()
    assert root.is_symlink()


def test_cleanup_waits_exact_code_images_before_any_unlink(published,monkeypatch):
    from pc_agent.platform.windows import support_access_native as native
    module,profile,m=published;events=[];original=Path.unlink
    class Processes:
        def __init__(self,path):events.append(('capture',path.name))
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def wait(self,*,timeout):assert timeout<=15;events.append('wait')
    def unlink(path,*args,**kwargs):
        assert events.count('wait')==len([r for r in m['runtime_files'] if r['path'].endswith('.exe')])
        events.append(('unlink',path.name));return original(path,*args,**kwargs)
    monkeypatch.setattr(native,'OwnedImageProcesses',Processes);monkeypatch.setattr(Path,'unlink',unlink)
    module.remove()
    assert events[-1]==('unlink',module.MARKER)
