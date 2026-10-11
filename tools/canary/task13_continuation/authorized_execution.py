"""One new actual authorization after fixed independently audited observation."""
from pathlib import Path
from .codec import canonical,digest,instant,parse_json,require,sha256
from .storage import ProtectedStore
from .receipt import observation,raw_bytes
from .reconciliation import validate_state
from . import windows

ROOT_NAME='task13-readonly-unknown-recovery-review-20261011-d'
PINS={
 'closure.json':'e5dafc8cf10fc47f8ab77c5defb617ae2f9168b036dcf6ce8310f42ce6821520',
 'review.json':'b1597df44ee66096e5d6db13f34817f1bddbcaebe8acdd2ce484d07af48d4409',
 'trust.json':'d0828ba7137f9887ae1caa25bdd6f73e1200bb06fab15da053fbeb430e015da7',
 'operator-request.json':'5ce1eff6ab2e9257cbb38b61a1c547aa830002caa879d3cd453d2f6649f75f7d',
 'observation-wrapper.py':'85c3f2adee4e655e0434fda4d271fb3f7ccac02652cabfe5ddacad69efcf9b77',
 'observation-wrapper-review.json':'a67e7615726f071952368f5021179f09472488ddbe86f0bd18544969602a8755',
 'observation-controller.json':'60449290b0b2e6f0aca81241d4fc16b01b5e87d22bee57beadcd25b288509353',
 'read-only-guard/window.json':'6086c0b17cd794911d7f91f3437a47a393881710876551a2a07643805a5cb7c1',
 'read-only-guard/preflight.json':'141aa1c332b335c0ce2564b8a533d9a9202a5b494430eb50f37586319ad53224',
 'read-only-guard/verdict.json':'94038b51c40debe1167a39473abd391334501ef469a917f269ca53f9921a356b',
 'postflight-preservation.json':'b4cd93b5035b043a6655ba60d1e4359e764463915e315bd634456a273de1e663',
 'independent-observation-audit.json':'66163b66b648fbec44a3e39b80c25dd76196213dfcc964ef421963ef97164832'}

def capture_admission(prefix=None):
    root=Path.home()/'.codex/task-evidence'/ROOT_NAME;data={}
    for name,pin in PINS.items():
        path=root/name;raw=ProtectedStore(path.parent).read(path.name)
        require(sha256(raw)==pin,'prior recovery admission pin changed')
        if name.endswith('.json'):data[name]=parse_json(raw)
    closure,review,trust=(data[n+'.json'] for n in ('closure','review','trust'))
    window,preflight,verdict=(data['read-only-guard/'+n+'.json'] for n in ('window','preflight','verdict'))
    outer=data['observation-controller.json'];audit=data['independent-observation-audit.json']
    require(review['status']=='PASS' and review['source_closure_sha256']==digest(closure)==trust['source_closure_sha256']
            and digest(review)==trust['review_sha256'],'prior independent source review')
    require(verdict['status']=='READ_ONLY_CANONICAL_PREFLIGHT_PASS' and verdict['historical_rca']=='UNKNOWN'
            and verdict['seq04_authorized'] is False and verdict['seq04_dispatched'] is False
            and verdict['claims_consumed'] is False and verdict['consumed_claim_unchanged'] is True
            and verdict['preflight_sha256']==digest(preflight) and verdict['original']==closure['original_binding'],
            'fixed prior read-only recovery gate')
    require(audit['status']=='PASS' and audit['original']==verdict['original']
            and audit['source_closure_sha256']==digest(closure) and audit['historical_rca']=='UNKNOWN'
            and audit['consumed_claim_unchanged'] is True and audit['seq04_authorized'] is False
            and audit['seq04_dispatched'] is False and audit['receipt04_present'] is False,
            'fixed independent observation audit')
    require(window['schema']=='task13_readonly_gate_window_v1'
            and window['deadline_mono_ns']-window['created_mono_ns']==1200*10**9
            and (instant(window['expires_utc'])-instant(window['created_utc'])).total_seconds()==1200,'prior window duration')
    require(outer['pid']==window['controller']['pid'] and outer['birth']==window['controller']['birth']
            and outer['wait_result']==0 and outer['exit_code']==0 and outer['streams_complete'] is True
            and outer['timed_out'] is False and outer['seq04_dispatched'] is False,'prior actual root completion')
    stdout,stderr=(raw_bytes(outer[k+'_b64']) for k in ('stdout','stderr'))
    require(not stderr and sha256(stdout)==outer['stdout_sha256'] and sha256(stderr)==outer['stderr_sha256']
            and parse_json(stdout)==verdict,'prior complete root verdict')
    require(instant(window['created_utc'])<=instant(preflight['finished_utc'])<=instant(verdict['checked_utc'])
            <=instant(outer['observed_exit_utc'])<=instant(window['expires_utc']),'prior gate chronology')
    state=observation(preflight,window,maximum=60)
    if prefix is not None:
        require(verdict['original']==prefix.binding,'prior recovery prefix changed')
        validate_state(prefix,window,state,preflight['finished_utc'])
    return dict(schema='task13_seq04_recovery_admission_v1',status='PRIOR_READONLY_RECOVERY_VERIFIED',
                original=verdict['original'],historical_rca='UNKNOWN',files_sha256=dict(PINS),
                preflight_sha256=digest(preflight),checked_utc=verdict['checked_utc'])

def hold_admission(stack,expected,prefix):
    root=Path.home()/'.codex/task-evidence'/ROOT_NAME
    for path in reversed((root,*root.parents)):
        stack.enter_context(windows.retained(path,directory=True,protected=path==root,security=path==root))
    stack.enter_context(windows.retained(root/'read-only-guard',directory=True,protected=True))
    for name,pin in PINS.items():
        path=root/name;handle=stack.enter_context(windows.retained(path,protected=True))
        require(sha256(windows.read_handle(handle,path))==pin,'held prior recovery gate changed')
    require(capture_admission(prefix)==expected,'prior recovery admission changed')

def launch_path(prefix,request):
    key={k:prefix.binding[k] for k in ('original_run_seal_sha256','original_tip')}
    key.update(authorization_record_sha256=request['record_sha256'],admission_sha256=request['gate_admission_sha256'])
    return prefix.root/'continuation-v1-claims'/('execution-launch-'+digest(key)+'.json')

def launch_owner(prefix,request,closure):
    return dict(schema='task13_authorized_execution_launch_v1',allowed_seq=4,
                original_run_seal_sha256=prefix.binding['original_run_seal_sha256'],original_tip=prefix.binding['original_tip'],
                authorization_record_sha256=request['record_sha256'],request_sha256=digest(request),
                admission_sha256=request['gate_admission_sha256'],continuation_id=closure['continuation_id'],
                source_closure_sha256=digest(closure))

def check_launch(prefix,request,closure,*,child):
    path=launch_path(prefix,request)
    if child:
        require(path.exists(),'child requires permanent execution launch claim')
        require(parse_json(ProtectedStore(path.parent).read(path.name))==launch_owner(prefix,request,closure),
                'execution launch claim owner changed')
    else:require(not path.exists(),'authorized execution launch already consumed; no retry')

def claim_launch(prefix,request,closure):
    path=launch_path(prefix,request)
    try:store=ProtectedStore.create_root(path.parent)
    except OSError:store=ProtectedStore(path.parent)
    store.create(path.name,canonical(launch_owner(prefix,request,closure)))

def hold_launch(stack,prefix,request,closure,*,child):
    check_launch(prefix,request,closure,child=child)
    if child:
        path=launch_path(prefix,request);handle=stack.enter_context(windows.retained(path,protected=True))
        require(parse_json(windows.read_handle(handle,path))==launch_owner(prefix,request,closure),
                'held execution launch claim owner changed')
