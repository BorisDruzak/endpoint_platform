"""Process-local v2 readiness: expensive proof precedes fresh target clocks."""
import os
import stat as file_stat
import time
from pathlib import Path

from .codec import canonical,digest,instant,parse_json,require
from .sources import seal_sources
from .transport import utc,validate_command,validate_command_plan,powershell_argv
from .reconciliation import dispatch_freshness

_contexts={}
_issued={}
_PHASES={'supervisor-preclaim','supervisor-postclaim','child-preclaim','child-dispatch'}


class _Capability:
    __slots__=()
    def __new__(cls):raise TypeError('readiness capabilities are issued, never constructed')


def open_context(bundle):
    require(bundle['control']['protocol_version']==2 and bundle['control']['mode']=='execution'
        and id(bundle) not in _contexts,'one held v2 execution context')
    _contexts[id(bundle)]=dict(bundle=bundle,process=os.getpid(),held=bundle['held'],tokens=set(),phases=set())


def close_context(bundle):
    context=_contexts.pop(id(bundle),None)
    if context is not None:
        for token in context['tokens']:_issued.pop(token,None)


def _mint(context,kind,data):
    token=object.__new__(_Capability)
    _issued[token]=(context,kind,data);context['tokens'].add(token)
    return token


def _get(token,kind,auth):
    require(type(token) is _Capability and token in _issued,'issued process-local readiness required')
    context,actual,data=_issued[token];bundle=context['bundle']
    require(actual==kind and _contexts.get(id(bundle)) is context and context['process']==os.getpid()
        and context['held'] is bundle['held'] and data['auth'] is auth,'active exact held readiness owner')
    return context,data


def _bindings(bundle,auth):
    require(getattr(auth,'request',None)==bundle['request'],'live authorization request changed')
    return canonical(dict(capsule_sha256=digest(auth.capsule),request_sha256=digest(bundle['request']),
        gate_sha256=digest(bundle['gate']),history_sha256=digest(bundle['history']),closure_sha256=digest(bundle['closure']),
        control_sha256=digest(bundle['control']),operations_sha256=digest(bundle['operations']),
        execution=seal_sources(bundle['entries'])))


def _catalogue(root):
    def identity(path,kind):
        info=path.stat(follow_symlinks=False)
        attributes=getattr(info,'st_file_attributes',0)
        require(not attributes&file_stat.FILE_ATTRIBUTE_REPARSE_POINT
            and (file_stat.S_ISDIR(info.st_mode) if kind=='directory' else file_stat.S_ISREG(info.st_mode)),
            'historical catalogue type/reparse point')
        return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,attributes,
            getattr(info,'st_size',None),getattr(info,'st_mtime_ns',None),getattr(info,'st_ctime_ns',None))
    for ancestor in root.parents:identity(ancestor,'directory')
    identities={root:('directory',identity(root,'directory'))};rows=[]
    def inaccessible(error):raise ValueError('historical catalogue enumeration unavailable') from error
    for base,dirs,files in os.walk(root,followlinks=False,onerror=inaccessible):
        base=Path(base)
        require(base in identities and identity(base,'directory')==identities[base][1],
            'historical catalogue directory changed')
        for name,kind in [(n,'directory') for n in dirs]+[(n,'file') for n in files]:
            path=base/name;identities[path]=(kind,identity(path,kind))
            rows.append((path.relative_to(root).as_posix(),kind))
            require(len(rows)<=10000,'bounded historical catalogue')
    for path,(kind,original) in identities.items():
        require(identity(path,kind)==original,'historical catalogue entry changed')
    return tuple(sorted(rows))


def _catalogues(bundle):
    from .recovery_admission import FAILED_NAME,READONLY_NAME
    home=Path.home()/'.codex/task-evidence'
    return {str(root):_catalogue(root) for root in (home/FAILED_NAME,home/READONLY_NAME,
        bundle['prefix'].root/'zero-owner-recovery-records')}


def prepare_readiness(bundle,auth,phase,seconds=420):
    from .recovery_admission import capture_history
    from .recovery_bundle import verify_feasibility
    from .recovery_loader import fresh_previous,root_argv,entry_flag,require_budget
    from .recovery_permission_v2 import verify_recovery_permission
    context=_contexts.get(id(bundle))
    require(context is not None and context['bundle'] is bundle and context['process']==os.getpid()
        and phase in _PHASES and phase not in context['phases'],'one preparation per held phase')
    auth.check();verify_recovery_permission(bundle['request'],bundle['gate']);require_budget(auth,seconds)
    started_utc,started_ns=utc(),time.monotonic_ns()
    catalogues=_catalogues(bundle)
    require(capture_history(bundle['prefix'])==bundle['history'],'prepared historical identities changed')
    fresh_previous(bundle['history'])
    argv=root_argv(bundle['root'],bundle['control'],entry_flag(bundle['control'],'execute-child'))
    plan=verify_feasibility(bundle['prefix'],bundle['closure'],bundle['entries'],bundle['operations'],argv)
    bindings=_bindings(bundle,auth)
    require(_catalogues(bundle)==catalogues,'historical catalogue changed during full verification')
    auth.check();require_budget(auth,seconds)
    finished_utc,finished_ns=utc(),time.monotonic_ns()
    manifest=dict(schema='task13_prepared_readiness_v2',phase=phase,source_closure_sha256=digest(bundle['closure']),
        capsule_sha256=digest(auth.capsule),history_sha256=digest(bundle['history']),command_plan=plan,
        bindings_sha256=digest(parse_json(bindings)),started_utc=started_utc,finished_utc=finished_utc,
        started_mono_ns=started_ns,finished_mono_ns=finished_ns)
    context['phases'].add(phase)
    return _mint(context,'prepared',dict(auth=auth,bindings=bindings,manifest=canonical(manifest),
        command_plan=canonical(plan),argv=tuple(argv),finished_utc=finished_utc,finished_ns=finished_ns,catalogues=catalogues))


def prepared_manifest(token,auth):
    _,data=_get(token,'prepared',auth);return parse_json(data['manifest'])


def reconcile_prepared(prepared,auth,transport):
    from .recovery_observation_v2 import reconcile
    from .receipt import observation
    context,data=_get(prepared,'prepared',auth);bundle=context['bundle']
    require(_bindings(bundle,auth)==data['bindings'],'prepared source/context bindings changed')
    require(not data.get('observed'),'prepared phase cannot replay observations')
    data['observed']=True
    raw=reconcile(bundle['prefix'],auth,transport,bundle['operations'],bundle['entries'],bundle['closure'])
    require(data['finished_ns']<=raw['dispatch_mono_ns'] and instant(data['finished_utc'])<=instant(raw['dispatch_utc']),
        'full preparation must precede actual fresh transports')
    state=observation(raw,auth.capsule,maximum=60)
    freshness=dispatch_freshness(state)
    auth.check();freshness(utc())
    raw=dict(raw,prepared_readiness_sha256=digest(parse_json(data['manifest'])))
    return _mint(context,'fresh',dict(auth=auth,prepared=prepared,raw=canonical(raw),freshness=freshness,
        manifest=canonical(dict(schema='task13_validated_fresh_reconciliation_v2',
            prepared_sha256=digest(parse_json(data['manifest'])),preflight_sha256=digest(raw),
            capsule_sha256=digest(auth.capsule),source_closure_sha256=digest(bundle['closure'])))))


def raw_reconciliation(token,auth):
    _,data=_get(token,'fresh',auth);return parse_json(data['raw'])


def fresh_manifest(token,auth):
    _,data=_get(token,'fresh',auth);return parse_json(data['manifest'])


def require_ready(prepared,fresh,auth,argv,seconds=420):
    from .recovery_loader import require_budget
    from .recovery_permission_v2 import verify_recovery_permission
    context,data=_get(prepared,'prepared',auth);owner,live=_get(fresh,'fresh',auth)
    require(owner is context and live['prepared'] is prepared,'freshness belongs to exact prepared review')
    bundle=context['bundle'];auth.check();verify_recovery_permission(bundle['request'],bundle['gate']);require_budget(auth,seconds)
    require(not (bundle['root']/'no-pyc').exists() and _catalogues(bundle)==data['catalogues'],
        'held historical catalogue/cache changed after full verification')
    require(_bindings(bundle,auth)==data['bindings'],'final prepared bindings changed')
    plan=validate_command_plan(bundle['operations'],bundle['entries']);plan['root']=validate_command(list(data['argv']))
    joint=powershell_argv(bundle['operations']['guest_ssh'],bundle['entries']['delivery-joint_identity.ps1'].decode())
    plan['joint_identity']=validate_command(joint,remote_command=joint[-1])
    require(canonical(plan)==data['command_plan'],'final exact command plan changed')
    workload=powershell_argv(bundle['operations']['guest_ssh'],bundle['entries']['delivery-workload.ps1'].decode())
    require(tuple(argv) in (data['argv'],tuple(workload)),'exact prepared launch/dispatch argv required')
    def final(at):
        _get(prepared,'prepared',auth);_get(fresh,'fresh',auth)
        auth.check();verify_recovery_permission(bundle['request'],bundle['gate']);require_budget(auth,seconds)
        require(not (bundle['root']/'no-pyc').exists() and _catalogues(bundle)==data['catalogues'],
            'final historical catalogue/cache changed')
        require(_bindings(bundle,auth)==data['bindings'],'dispatch bindings changed')
        live['freshness'](at);live['freshness'](utc())
    auth.check();require_budget(auth,seconds);final(utc())
    return final


def validate_recorded_readiness(parent,capsule,evidence):
    """Historical proof metadata only; never recreates process-local authority."""
    from .codec import integer,hex256
    phases={'supervisor-preclaim':(parent,evidence['launch_preflight']),
        'supervisor-postclaim':(parent,evidence['launch_postclaim_preflight']),
        'child-preclaim':(capsule,evidence['preclaim_preflight']),
        'child-dispatch':(capsule,evidence['preflight'])}
    records=evidence['prepared_readiness']
    require(type(records) is dict and set(records)=={p+'-'+k for p in phases for k in ('prepared','fresh')},
        'all eight separate recorded readiness bindings required')
    for phase,(c,raw) in phases.items():
        prepared,fresh=(records[phase+'-'+k] for k in ('prepared','fresh'))
        require(type(prepared) is dict and set(prepared)=={'schema','phase','source_closure_sha256','capsule_sha256',
            'history_sha256','command_plan','bindings_sha256','started_utc','finished_utc','started_mono_ns','finished_mono_ns'}
            and prepared['schema']=='task13_prepared_readiness_v2' and prepared['phase']==phase
            and prepared['source_closure_sha256']==digest(c['source_closure']) and prepared['capsule_sha256']==digest(c)
            and prepared['history_sha256']==digest(evidence['recovery_history']),'recorded prepared source/capsule/phase binding')
        require(raw.get('prepared_readiness_sha256')==digest(prepared),
            'exact recorded command/proof manifest bound before slot/preflight hashing')
        pins=c['source_closure']['execution']['entries']
        bindings=dict(capsule_sha256=digest(c),request_sha256=digest(evidence['recovery_authorization']),
            gate_sha256=digest(evidence['admission_gate']),history_sha256=digest(evidence['recovery_history']),
            closure_sha256=digest(c['source_closure']),control_sha256=pins['control.json']['sha256'],
            operations_sha256=pins['operations.json']['sha256'],execution=c['source_closure']['execution'])
        require(prepared['bindings_sha256']==digest(bindings),'recorded immutable prepared bindings')
        require(instant(c['created_utc'])<=instant(prepared['started_utc'])<=instant(prepared['finished_utc'])
            <=instant(raw['dispatch_utc'])<=instant(raw['finished_utc'])<instant(c['expires_utc'])
            and c['created_mono_ns']<=integer(prepared['started_mono_ns'])<=integer(prepared['finished_mono_ns'])
            <=raw['dispatch_mono_ns']<=raw['finished_mono_ns']<c['deadline_mono_ns']-2*10**9,
            'expensive verification must precede recorded fresh transports')
        require(abs((instant(prepared['finished_utc'])-instant(prepared['started_utc'])).total_seconds()
            -(prepared['finished_mono_ns']-prepared['started_mono_ns'])/10**9)<=5,'prepared verification clocks diverged')
        plan=prepared['command_plan']
        require(type(plan) is dict and set(plan)=={'clock_guest','collect','current','guest','inventory','joint_identity',
            'management','prepare','process_identity','provider','root','workload'},'recorded complete command plan')
        for name,row in plan.items():
            remote=name not in ('root','management','provider')
            require(type(row) is dict and set(row)==({'utf16_units_with_nul','command_sha256','remote_utf16_units_with_nul'}
                if remote else {'utf16_units_with_nul','command_sha256'}),'recorded command bound fields')
            integer(row['utf16_units_with_nul'],1,8191);hex256(row['command_sha256'])
            if remote:integer(row['remote_utf16_units_with_nul'],1,8191)
        require(type(fresh) is dict and set(fresh)=={'schema','prepared_sha256','preflight_sha256','capsule_sha256','source_closure_sha256'}
            and fresh==dict(schema='task13_validated_fresh_reconciliation_v2',prepared_sha256=digest(prepared),
                preflight_sha256=digest(raw),capsule_sha256=digest(c),source_closure_sha256=digest(c['source_closure'])),
            'recorded actual observer/prepared/source/capsule binding')
