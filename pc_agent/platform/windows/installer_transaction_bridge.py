"""Offline client for the fixed PowerShell installer owner.

The owner remains on its mutex-owning thread. This module never acquires the
product mutex, starts a listener, clears an abandoned fence, or imports Setup.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import struct
import uuid

from endpoint_contracts.runtime_payload import read_json, reject_reparse_ancestors
from .installer_fence import assert_state_security, state_root
from .update_paths import WindowsUpdatePaths

PHASES = frozenset({'inspect','prepare','msi-preflight','msi-enter','recover-enter',
    'foundation-config','msi-complete','reconcile','finish','verify-settled',
    'uninstall-finalize-preflight','uninstall-finalize-enter','uninstall-finalize-complete'})
_HASH = re.compile(r'\A[0-9a-f]{64}\Z')
_CAP_FIELDS = {'schema_version','transaction_id','session_id','package','operation','pipe_name','owner',
    'helper_sha256','secret','selected','previous','service_states','recovery','uninstall_finalization'}


def _failed():
    raise ValueError('OWNER_AUTH_FAILED')


class InstallerServices:
    """Fixed installer SCM configuration, with handles retained through readback.

    No start/stop operation exists here. A running legacy worker always wins.
    The authenticated phase persists its original snapshot before calling quarantine.
    """
    def __init__(self,paths,*,api=None,checkpoint=lambda:None,flush=None):
        if api is None:
            import win32service as api
        self.api=api;self.paths=paths;self.checkpoint=checkpoint
        self.flush=flush or self._flush_service
        self.stack=ExitStack();self.handles={}

    def __enter__(self):
        try:
            scm=self.api.OpenSCManager(None,None,1)
            self.stack.callback(self.api.CloseServiceHandle,scm)
            for name in ('EndpointAgent','EndpointAgentUpdater'):
                try: handle=self.api.OpenService(scm,name,1|2|4)
                except Exception as error:
                    if getattr(error,'winerror',None)!=1060: raise
                    handle=None
                if handle is not None: self.stack.callback(self.api.CloseServiceHandle,handle)
                self.handles[name]=handle
            return self
        except BaseException:
            self.stack.close();raise

    def __exit__(self,*args):
        return self.stack.__exit__(*args)

    @staticmethod
    def _flush_service(name):
        import winreg
        if name not in {'EndpointAgent','EndpointAgentUpdater'}: _failed()
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            'SYSTEM\\CurrentControlSet\\Services\\'+name,0,winreg.KEY_QUERY_VALUE|winreg.KEY_WOW64_64KEY) as key:
            winreg.FlushKey(key)

    def snapshot(self):
        result={}
        for name,handle in self.handles.items():
            if handle is None:
                result[name]=None;continue
            config=self.api.QueryServiceConfig(handle)
            filename,argument,account=(('endpoint-agent-service.exe','--agent-service',r'NT AUTHORITY\LocalService')
                if name=='EndpointAgent' else ('endpoint-agent-updater.exe','--updater-service','LocalSystem'))
            path=str(self.paths.install_root/filename)
            commands={f'"{path}" {argument}'.casefold()}
            if not any(char.isspace() for char in path): commands.add(f'{path} {argument}'.casefold())
            if config[0]!=16 or config[1] not in {2,3,4} or config[3].casefold() not in commands or config[7].casefold()!=account.casefold():
                raise ValueError('PROVENANCE_CONFLICT')
            delayed=self.api.QueryServiceConfig2(handle,3)
            if type(delayed) is not bool: raise ValueError('UPDATE_STATE_INVALID')
            if self.api.QueryServiceStatus(handle)[1]!=1: raise ValueError('UPDATE_IN_PROGRESS')
            result[name]={'start_type':config[1],'delayed_auto':delayed}
        return result

    def _apply(self,desired):
        # Validate both registrations before the first configuration mutation.
        current=self.snapshot()
        if {name for name,value in current.items() if value is None}!={name for name,value in desired.items() if value is None}:
            raise ValueError('PROVENANCE_CONFLICT')
        for name,value in desired.items():
            if value is None: continue
            handle=self.handles[name]
            if current[name]['start_type']!=value['start_type']:
                self.checkpoint()
                self.api.ChangeServiceConfig(handle,0xffffffff,value['start_type'],0xffffffff,None,None,0,None,None,None,None)
            if current[name]['delayed_auto']!=value['delayed_auto']:
                self.checkpoint()
                self.api.ChangeServiceConfig2(handle,3,value['delayed_auto'])
            # SCM readback alone observes cache. Even an exact retry requires
            # the persistence barrier before native mutation/fence retirement.
            self.checkpoint()
            self.flush(name)
        if self.snapshot()!=desired: raise ValueError('RECOVERY_REQUIRED')

    def quarantine(self,original,*,recovery=False):
        current=self.snapshot()
        if not recovery and current!=original: raise ValueError('PROVENANCE_CONFLICT')
        self._apply({name:None if value is None else {**value,'start_type':4} for name,value in current.items()})

    def assert_quarantined(self):
        if any(value is not None and value['start_type']!=4 for value in self.snapshot().values()):
            raise ValueError('RECOVERY_REQUIRED')

    def restore_final(self):
        self._apply({'EndpointAgent':{'start_type':2,'delayed_auto':False},
            'EndpointAgentUpdater':{'start_type':3,'delayed_auto':False}})

    def restore_original(self,original):
        # Caller must already have established the approved native barrier and
        # exact coherent original installation; this method supplies no authority.
        self._apply(original)


def validate_feature_plan(operation,states,*,rollback_disabled,recovery=False,finalization=False):
    """Validate costing's actual feature states, independently of REMOVE text."""
    if (len(states)!=4 or any(type(value) is not int or value not in {-1,1,2,3} for value in states)
        or rollback_disabled not in {'','0'}):
        _failed()
    foundation_before,foundation_after,runtime_before,runtime_after=states
    if finalization:
        valid=operation=='uninstall' and recovery is True and all(value in {-1,2} for value in states)
    elif operation=='install':
        valid=foundation_after==runtime_after==3
    elif operation=='retire-initial-runtime':
        valid=foundation_before==foundation_after==3 and runtime_before in ((2,3) if recovery else (3,)) and runtime_after==2
    elif operation=='uninstall':
        valid=foundation_before==3 and foundation_after==runtime_after==2
    else:
        valid=False
    if not valid: _failed()


def _uuid(value):
    if not isinstance(value,str) or str(uuid.UUID(value)) != value:
        _failed()
    return value


def _identity(value):
    if (not isinstance(value,dict) or set(value) != {'pid','created','hash','sid','elevated'}
        or type(value['pid']) is not int or value['pid'] <= 0
        or type(value['created']) is not int or value['created'] <= 0
        or not isinstance(value['hash'],str) or not _HASH.fullmatch(value['hash'])
        or not isinstance(value['sid'],str) or not re.fullmatch(r'S-1-[0-9-]+',value['sid'])
        or value['elevated'] is not True):
        _failed()
    return value


def _read_capability(paths,session_id):
    _uuid(session_id)
    root=state_root(paths)
    assert_state_security(root)
    directory=root/'capabilities'
    assert_state_security(directory,secret=True)
    path=directory/f'{session_id}.json'
    assert_state_security(path,secret=True)
    before=path.lstat()
    if before.st_nlink != 1 or not 0 < before.st_size <= 16384:
        _failed()
    with path.open('rb') as stream:
        payload=read_json(stream.read(16385),16384)
    after=path.lstat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        _failed()
    if (set(payload)!=_CAP_FIELDS or type(payload['schema_version']) is not int or payload['schema_version']!=1
        or payload['session_id']!=session_id
        or payload['operation'] not in {'install','retire-initial-runtime','uninstall'}
        or type(payload['recovery']) is not bool
        or type(payload['uninstall_finalization']) is not bool
        or (payload['uninstall_finalization'] and (not payload['recovery'] or payload['operation']!='uninstall'))
        or not isinstance(payload['helper_sha256'],str) or not _HASH.fullmatch(payload['helper_sha256'])
        or not isinstance(payload['secret'],str) or not _HASH.fullmatch(payload['secret'])
        or not isinstance(payload['pipe_name'],str)
        or not re.fullmatch(r'EndpointInstaller-'+re.escape(session_id)+r'-[0-9a-f]{32}',payload['pipe_name'])):
        _failed()
    _uuid(payload['transaction_id'])
    _identity(payload['owner'])
    for key in ('selected','previous'):
        if payload[key] is not None and (not isinstance(payload[key],str) or not _HASH.fullmatch(payload[key])):
            _failed()
    package=payload['package']
    if (not isinstance(package,dict) or set(package)!={'schema_version','package_sha256','product_code','version','source_revision','initial_runtime_tree_sha256'}
        or not isinstance(package['package_sha256'],str) or not _HASH.fullmatch(package['package_sha256'])):
        _failed()
    return payload


class NativeIdentity:
    """Retain the process and its opened image until the conversation ends."""
    def __init__(self,pid):
        import win32api
        import win32file
        import win32security
        self.stack=ExitStack()
        try:
            process=win32api.OpenProcess(0x00101000,False,pid)
            self.stack.callback(process.Close)
            self.process=process
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            query=kernel.QueryFullProcessImageNameW
            query.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
            query.restype=wintypes.BOOL
            path=ctypes.create_unicode_buffer(32768); length=wintypes.DWORD(len(path))
            if not query(int(process),0,path,ctypes.byref(length)):
                raise ctypes.WinError(ctypes.get_last_error())
            image_path=Path(path.value)
            reject_reparse_ancestors(image_path)
            image=win32file.CreateFile(str(image_path),0x80000000,1,None,3,0x00200000,None)
            self.stack.callback(image.Close)
            if win32file.GetFileInformationByHandle(image)[0]&0x400:
                _failed()
            digest=hashlib.sha256()
            while True:
                _,block=win32file.ReadFile(image,1024*1024)
                if not block: break
                digest.update(block)
            get_times=kernel.GetProcessTimes
            get_times.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(ctypes.c_uint64)]*4
            get_times.restype=wintypes.BOOL
            times=[ctypes.c_uint64() for _ in range(4)]
            if not get_times(int(process),*[ctypes.byref(value) for value in times]):
                raise ctypes.WinError(ctypes.get_last_error())
            token=win32security.OpenProcessToken(process,8)
            self.stack.callback(token.Close)
            sid=win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token,win32security.TokenUser)[0])
            elevated=bool(win32security.GetTokenInformation(token,win32security.TokenElevation)) or sid=='S-1-5-18'
            self.value=_identity({'pid':pid,'created':times[0].value,'hash':digest.hexdigest(),'sid':sid,'elevated':elevated})
            self.assert_alive()
        except BaseException:
            self.stack.close()
            raise

    def assert_alive(self):
        import win32event
        if win32event.WaitForSingleObject(self.process,0)!=win32event.WAIT_TIMEOUT:
            _failed()

    def close(self):
        self.stack.close()


class PipeTransport:
    def __init__(self,name):
        import win32file
        import win32pipe
        pipe_path='\\\\.\\pipe\\'+name
        win32pipe.WaitNamedPipe(pipe_path,5000)
        # Read/write data without FILE_CREATE_PIPE_INSTANCE, overlapped and no
        # impersonation grant. All messages have an explicit upper bound.
        self.handle=win32file.CreateFile(pipe_path,0x0012019B,0,None,3,0x40000000|0x00100000,None)

    def _io(self,data,*,writing):
        import pywintypes
        import win32event
        import win32file
        operation=pywintypes.OVERLAPPED()
        operation.hEvent=win32event.CreateEvent(None,True,False,None)
        try:
            if writing:
                win32file.WriteFile(self.handle,data,operation)
                buffer=data
            else:
                _,buffer=win32file.ReadFile(self.handle,data,operation)
            if win32event.WaitForSingleObject(operation.hEvent,30000)!=win32event.WAIT_OBJECT_0:
                win32file.CancelIoEx(self.handle,operation)
                try: win32file.GetOverlappedResult(self.handle,operation,True)
                except pywintypes.error: pass
                _failed()
            size=win32file.GetOverlappedResult(self.handle,operation,False)
            if size<=0: _failed()
            return size if writing else bytes(buffer[:size])
        finally:
            operation.hEvent.Close()

    def send(self,value):
        raw=json.dumps(value,separators=(',',':'),allow_nan=False).encode('ascii')
        if not 0<len(raw)<=32768: _failed()
        frame=struct.pack('<I',len(raw))+raw
        while frame:
            frame=frame[self._io(frame,writing=True):]

    def receive(self):
        def exact(size):
            result=bytearray()
            while len(result)<size:
                result.extend(self._io(size-len(result),writing=False))
            return bytes(result)
        length=struct.unpack('<I',exact(4))[0]
        if not 0<length<=32768: _failed()
        return read_json(exact(length),32768)

    def close(self):
        self.handle.Close()


class BridgeClient:
    def __init__(self,capability,phase,transport,identity,owner):
        if phase not in PHASES: _failed()
        self.capability,self.phase,self.transport=capability,phase,transport
        self.identity,self.owner=identity,owner
        self.sequence=0
        self.secret=bytes.fromhex(capability['secret'])
        self.begun=False
        self.complete=False

    def _sign(self,prefix,transcript):
        return hmac.new(self.secret,(prefix+'|'+transcript).encode('ascii'),'sha256').hexdigest()

    def request(self,action,payload=None):
        if self.complete or action not in {'begin','mutation','complete'} or (action=='begin')==self.begun:
            _failed()
        self.owner.assert_alive()
        self.identity.assert_alive()
        raw=json.dumps(payload,separators=(',',':'),allow_nan=False).encode('ascii')
        if len(raw)>8192: _failed()
        payload_hash=hashlib.sha256(raw).hexdigest()
        self.transport.send({'phase':self.phase,'action':action,'payload':raw.hex(),'session':self.capability['session_id']})
        value=self.transport.receive()
        if (set(value)!={'sequence','nonce','proof'} or type(value['sequence']) is not int
            or not self.sequence<value['sequence']<=100000 or not isinstance(value['nonce'],str)
            or not _HASH.fullmatch(value['nonce'])):
            _failed()
        peer=self.identity.value
        transcript='|'.join(map(str,('1',self.capability['transaction_id'],self.capability['session_id'],self.capability['package']['package_sha256'],
            self.capability['operation'],self.phase,action,value['sequence'],peer['pid'],peer['created'],value['nonce'],payload_hash)))
        if not isinstance(value['proof'],str) or not hmac.compare_digest(self._sign('owner',transcript),value['proof']):
            _failed()
        self.transport.send({'proof':self._sign('request',transcript)})
        grant=self.transport.receive()
        if (set(grant)!={'sequence','proof'} or grant['sequence']!=value['sequence']
            or not isinstance(grant['proof'],str) or not hmac.compare_digest(self._sign('grant',transcript),grant['proof'])):
            _failed()
        self.sequence=value['sequence']
        self.begun=True
        if action=='complete':
            self.complete=True
            self.transport.send({'received':self.sequence})

    def checkpoint(self):
        self.request('mutation')


@contextmanager
def owner_authorized_phase(session_id,phase):
    """Connect only through the fixed protected capability locator."""
    paths=WindowsUpdatePaths.production()
    capability=_read_capability(paths,session_id)
    if capability['uninstall_finalization'] and phase in {'msi-preflight','msi-enter','msi-complete'}:
        phase=phase.replace('msi-','uninstall-finalize-')
    elif phase=='msi-enter' and capability['recovery']:
        phase='recover-enter'
    with ExitStack() as stack:
        transport=PipeTransport(capability['pipe_name']);stack.callback(transport.close)
        import win32pipe
        owner=NativeIdentity(win32pipe.GetNamedPipeServerProcessId(transport.handle));stack.callback(owner.close)
        if owner.value!=capability['owner']: _failed()
        identity=NativeIdentity(os.getpid());stack.callback(identity.close)
        if identity.value['hash']!=capability['helper_sha256']: _failed()
        client=BridgeClient(capability,phase,transport,identity,owner)
        client.request('begin')
        yield client


def _request_data(paths,capability):
    package=capability['package']
    return {'package_path':state_root(paths).parent/'installer-cache'/f"msi-{package['package_sha256']}"/'EndpointAgent.msi',
        'release':package,'transaction_id':capability['transaction_id'],
        'selected':capability['selected'],'previous':capability['previous']}


def _digests(inspected):
    return {'selected':inspected.current.digest if inspected.current else None,
        'previous':inspected.previous.digest if inspected.previous else None}


def _matching_inspection(paths,expected,capability,*,retirement=False):
    from .installation_provenance import inspect_installed_core,inspect_runtime_retirement
    inspected=(inspect_runtime_retirement(paths,expected,recovery=capability.get('recovery',False)) if retirement else
        inspect_installed_core(paths,resulting_foundation=expected.package.version))
    if _digests(inspected)!={key:capability[key] for key in ('selected','previous')}:
        raise ValueError('PROVENANCE_CONFLICT')
    return inspected


def _public_fence(expected,capability,service_startup=None):
    return {'schema_version':1,'transaction_id':capability['transaction_id'],'phase':'prepared',
        'operation':capability['operation'],'package':{'sha256':expected.package.sha256,
            'product_code':expected.package.product_code,'package_code':expected.package.package_code,
            'version':expected.package.version,'source_revision':expected.identity.source_revision},
        'selected':capability['selected'],'previous':capability['previous'],
        'service_states':capability['service_states'],
        'service_startup':service_startup or {'EndpointAgent':None,'EndpointAgentUpdater':None},
        'startup_restored':False,'sequence':0,'helpers':[]}


def _advance_fence(paths,client,expected,phase):
    from .installer_fence import read_fence,publish_fence
    fence=read_fence(paths)
    expected_fence=_public_fence(expected,client.capability)
    if fence is None or any(fence[key]!=expected_fence[key] for key in ('transaction_id','package','operation','selected','previous','service_states')):
        raise ValueError('PROVENANCE_CONFLICT')
    fence['phase']=phase
    fence['sequence']+=1
    peer=client.identity.value
    if len(fence['helpers'])>=64: _failed()
    fence['helpers'].append({'pid':peer['pid'],'creation_time':peer['created'],'image_sha256':peer['hash'],
        'phase':phase,'complete':True})
    publish_fence(paths,fence)
    return fence


def _settled(paths):
    from .update_transaction import active_update_state
    if active_update_state(paths) is not None:
        raise ValueError('UPDATE_IN_PROGRESS')


def execute_authorized_phase(client,paths,*,feature_states=None,rollback_disabled='',uninstall_finalization=''):
    """One fixed phase after native peer authentication; no mutex reacquisition."""
    from . import durable_state,installation_provenance as provenance,msi_inventory
    from .installer_fence import read_fence,publish_fence,protect_state
    capability=client.capability
    request=_request_data(paths,capability)
    expected=msi_inventory.read_expected_package(request['package_path'],capability['package'])
    phase=client.phase
    result={}
    if phase=='inspect':
        _settled(paths)
        if capability['recovery']:
            fence=read_fence(paths)
            if fence is None or fence['package']!=_public_fence(expected,capability)['package']:
                raise ValueError('PROVENANCE_CONFLICT')
            if capability['operation']=='install':
                provenance.validate_interrupted_reconciliation(paths,request)
            else:
                provenance.validate_maintenance_recovery(paths,request,capability['operation'])
                if capability['operation']=='retire-initial-runtime': _matching_inspection(paths,expected,capability,retirement=True)
            result={key:fence[key] for key in ('selected','previous')}
            result['uninstall_finalization']=False
            if capability['operation']=='uninstall' and msi_inventory.NativeMsi().product(expected.package.product_code)==-1:
                msi_inventory.verify_uninstalled(expected.package,paths.install_root)
                result['uninstall_finalization']=True
        else:
            if read_fence(paths) is not None: raise ValueError('UPDATE_IN_PROGRESS')
            inspected=(provenance.inspect_runtime_retirement(paths,expected) if capability['operation']=='retire-initial-runtime' else
                provenance.inspect_installed_core(paths,resulting_foundation=expected.package.version))
            result=_digests(inspected)
    elif phase=='verify-settled':
        _settled(paths)
        if read_fence(paths) is not None: raise ValueError('UPDATE_IN_PROGRESS')
        inspected=provenance.inspect_installed_core(paths,resulting_foundation=expected.package.version)
        if inspected.current is None: raise ValueError('PROVENANCE_CONFLICT')
        result={'settled':True,**_digests(inspected)}
    elif phase in {'msi-preflight','uninstall-finalize-preflight'}:
        finalization=phase=='uninstall-finalize-preflight'
        if uninstall_finalization!=('1' if finalization else ''): _failed()
        validate_feature_plan(capability['operation'],feature_states,rollback_disabled=rollback_disabled,
            recovery=capability['recovery'],finalization=finalization)
        fence=read_fence(paths)
        if fence is None or any(fence[key]!=_public_fence(expected,capability)[key] for key in
            ('transaction_id','package','operation','selected','previous')):
            raise ValueError('PROVENANCE_CONFLICT')
        if capability['recovery']:
            if capability['operation']=='install': provenance.validate_interrupted_reconciliation(paths,request)
            else:
                provenance.validate_maintenance_recovery(paths,request,capability['operation'])
                if capability['operation']=='retire-initial-runtime': _matching_inspection(paths,expected,capability,retirement=True)
                if finalization: msi_inventory.verify_uninstalled(expected.package,paths.install_root)
        else:
            _matching_inspection(paths,expected,capability,retirement=capability['operation']=='retire-initial-runtime')
        if capability['operation']!='retire-initial-runtime':
            with InstallerServices(paths) as services: services.assert_quarantined()
    else:
        with durable_state.installer_mutation_checkpoints(client.checkpoint):
            if phase=='prepare':
                _settled(paths)
                if capability['recovery']:
                    fence=read_fence(paths)
                    if fence is None or any(fence[key]!=_public_fence(expected,capability)[key] for key in ('transaction_id','package','operation','selected','previous')):
                        raise ValueError('PROVENANCE_CONFLICT')
                    # Recovery preparation only re-applies persistent quarantine.
                    # Core/receipt recovery still waits for serialized native entry.
                    if capability['operation']=='install': provenance.validate_interrupted_reconciliation(paths,request)
                    else: provenance.validate_maintenance_recovery(paths,request,capability['operation'])
                else:
                    if read_fence(paths) is not None: raise ValueError('UPDATE_IN_PROGRESS')
                    _matching_inspection(paths,expected,capability,retirement=capability['operation']=='retire-initial-runtime')
                if not capability['recovery'] and capability['operation']=='install':
                    result={'result':provenance.prepare_installer_provenance(paths,request)}
                    # Archives are inert until the entire prepared plan and the
                    # still-selected identities have been revalidated.
                    provenance.validate_interrupted_reconciliation(paths,request)
                elif not capability['recovery']:
                    provenance.prepare_maintenance_provenance(paths,request,capability['operation'])
                _settled(paths)
                if not capability['recovery']:
                    _matching_inspection(paths,expected,capability,retirement=capability['operation']=='retire-initial-runtime')
                if capability['operation']=='retire-initial-runtime':
                    if not capability['recovery']: publish_fence(paths,_public_fence(expected,capability))
                else:
                    with InstallerServices(paths,checkpoint=client.checkpoint) as services:
                        original=(fence['service_startup'] if capability['recovery'] else services.snapshot())
                        if not capability['recovery']: publish_fence(paths,_public_fence(expected,capability,original))
                        services.quarantine(original,recovery=capability['recovery'])
                        _settled(paths)
                        if not capability['recovery']: _matching_inspection(paths,expected,capability)
                if not capability['recovery']: _advance_fence(paths,client,expected,'msi-starting')
            elif phase=='uninstall-finalize-enter':
                if not capability.get('uninstall_finalization') or capability['operation']!='uninstall' or not capability['recovery']: _failed()
                provenance.validate_maintenance_recovery(paths,request,'uninstall')
                absence=msi_inventory.verify_uninstalled(expected.package,paths.install_root)
                fence=read_fence(paths)
                next_phase='msi-executing' if fence['phase'] in {'prepared','msi-starting','msi-executing'} else fence['phase']
                _advance_fence(paths,client,expected,next_phase)
                archive=provenance._archive_directory(provenance._archive_directory(state_root(paths),'transactions'),capability['transaction_id'])
                barrier={'schema_version':1,'transaction_id':capability['transaction_id'],'session_id':capability['session_id'],
                    'package_sha256':expected.package.sha256,'result':'uninstall-finalization-barrier-passed','postconditions':absence}
                durable_state.write_json_atomic(archive/('barrier-'+capability['session_id']+'.json'),barrier,
                    trusted_root=archive,max_bytes=16384,protect=protect_state)
            elif phase in {'msi-enter','recover-enter'}:
                _settled(paths)
                if phase=='recover-enter':
                    if not capability['recovery']: _failed()
                    if capability['operation']=='install': provenance.validate_interrupted_reconciliation(paths,request)
                    else:
                        provenance.validate_maintenance_recovery(paths,request,capability['operation'])
                        if capability['operation']=='retire-initial-runtime': _matching_inspection(paths,expected,capability,retirement=True)
                else:
                    _matching_inspection(paths,expected,capability,retirement=capability['operation']=='retire-initial-runtime')
                # recover-enter is granted only inside the genuine serialized
                # deferred script. No external idle/PID predicate reaches here.
                fence=read_fence(paths)
                next_phase='msi-executing' if fence['phase'] in {'prepared','msi-starting','msi-executing'} else fence['phase']
                _advance_fence(paths,client,expected,next_phase)
                if capability['operation']!='retire-initial-runtime':
                    from .service_launcher import stop_tray_companions
                    client.checkpoint()
                    stop_tray_companions(paths)
            elif phase=='foundation-config':
                if capability['operation']!='install': _failed()
                from .acl import apply_machine_data_acl,apply_tray_status_acl
                from .service_control import configure_service_sids,restrict_updater_start_permissions
                fence=read_fence(paths)
                _advance_fence(paths,client,expected,fence['phase'])
                for action in (configure_service_sids,apply_machine_data_acl,apply_tray_status_acl,restrict_updater_start_permissions):
                    client.checkpoint()
                    action()
            elif phase in {'msi-complete','uninstall-finalize-complete'}:
                fence=read_fence(paths)
                _advance_fence(paths,client,expected,fence['phase'])
            elif phase=='reconcile':
                fence=read_fence(paths)
                _advance_fence(paths,client,expected,'complete' if fence['phase']=='complete' else 'reconciling')
                if capability['operation']=='install':
                    result={'result':provenance.reconcile_installed_core(paths,request)}
                elif capability['operation']=='retire-initial-runtime':
                    if msi_inventory.verify_foundation(expected.package,paths.install_root,expected=expected)!='foundation_only': raise ValueError('PROVENANCE_CONFLICT')
                    _matching_inspection(paths,expected,capability)
                    provenance.retire_maintenance_authority(paths,request,capability['operation'])
                    result={'result':'retired_initial_runtime'}
                else:
                    absence=msi_inventory.verify_uninstalled(expected.package,paths.install_root)
                    if capability.get('uninstall_finalization'):
                        barrier=state_root(paths)/'transactions'/capability['transaction_id']/('barrier-'+capability['session_id']+'.json')
                        assert_state_security(barrier)
                        observed=read_json(provenance._read(barrier,16384),16384)
                        if observed!={'schema_version':1,'transaction_id':capability['transaction_id'],'session_id':capability['session_id'],
                            'package_sha256':expected.package.sha256,'result':'uninstall-finalization-barrier-passed','postconditions':absence}:
                            raise ValueError('PROVENANCE_CONFLICT')
                    provenance.retire_maintenance_authority(paths,request,capability['operation'])
                    result={'result':'uninstalled'}
            elif phase=='finish':
                if capability['operation']=='install':
                    msi_inventory.verify_installed(expected.package,paths.install_root)
                    provenance.inspect_installed_core(paths,resulting_foundation=expected.package.version)
                    with msi_inventory.verified_foundation_bytes(expected,paths.install_root):
                        with InstallerServices(paths,checkpoint=client.checkpoint) as services: services.restore_final()
                elif capability['operation']=='retire-initial-runtime':
                    if msi_inventory.verify_foundation(expected.package,paths.install_root,expected=expected)!='foundation_only': raise ValueError('PROVENANCE_CONFLICT')
                    _matching_inspection(paths,expected,capability)
                else:
                    msi_inventory.verify_uninstalled(expected.package,paths.install_root)
                fence=_advance_fence(paths,client,expected,'complete')
                fence['startup_restored']=True
                publish_fence(paths,fence)
                archive=provenance._archive_directory(provenance._archive_directory(state_root(paths),'transactions'),capability['transaction_id'])
                durable_state.write_json_atomic(archive/'completed.json',fence,trusted_root=archive,max_bytes=16384,protect=protect_state)
                # Final mutation. The owner waits for this helper's explicit
                # completion and actual process exit before starting Agent.
                durable_state.durable_unlink(state_root(paths)/'transaction.json',trusted_root=state_root(paths))
            else:
                _failed()
    client.request('complete',result)
    return result
