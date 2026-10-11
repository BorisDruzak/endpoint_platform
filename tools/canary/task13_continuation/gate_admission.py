"""Pinned prior full read-only gate for the separately reviewed execution step.

Admission never substitutes for the fresh canonical preflight before seq04.
"""
from pathlib import Path

from .codec import canonical,digest,instant,parse_json,require,sha256
from .storage import ProtectedStore
from .receipt import observation
from .reconciliation import validate_state
from . import windows

ROOT_NAME='task13-pid-identity-review-20261011-a'
PINS={
 'closure.json':'97ea1d0e52b0d4540ef94590faa20236c1af7ab08899dfdd3f763d66952dddc1',
 'review.json':'96cf890749bb8541bcb939278fb66fd3eef0f815f03e3cbb3f96eed91d37bf4d',
 'trust.json':'e6addf8c23592fe02f6b02432570ce719c5fe97b0ad91e67d3636b09fe48cfb8',
 'operator-request.json':'c51c5ffef8a01bba667ad7010f78b8bbe29eef7fb8877559f78dd4354dcf5d9e',
 'observation-controller.json':'44d204bc3cbdd5cf7082a05790bd0d59665325d7db23fcd2ceea27450b2ac188',
 'read-only-guard/window.json':'f6a4eb76317bf9ca62b40c9a4235a9fd24ce6f13670b831a964fe3c98a67eb20',
 'read-only-guard/preflight.json':'81a6e331525bf15ee79c7d1b8131429397f5a8db7b6799e9d0335ed39138268b',
 'read-only-guard/verdict.json':'5886392602065777fe3c9550e3b18a8f91a785d051062c80df68dd127089f30a'}


def capture_gate(prefix=None):
    root=Path.home()/'.codex/task-evidence'/ROOT_NAME
    data={}
    for name,pin in PINS.items():
        path=root/name
        raw=ProtectedStore(path.parent).read(path.name)
        require(sha256(raw)==pin,'prior read-only gate pin changed')
        data[name]=parse_json(raw)
    closure,review,trust=(data[n+'.json'] for n in ('closure','review','trust'))
    window,preflight,verdict=(data['read-only-guard/'+n+'.json'] for n in ('window','preflight','verdict'))
    controller=data['observation-controller.json']
    require(review['status']=='PASS' and review['source_closure_sha256']==digest(closure)
            and trust['review_sha256']==digest(review) and trust['source_closure_sha256']==digest(closure),'prior independent source review')
    require(verdict['status']=='READY_FOR_SEPARATE_SEQ04' and verdict['seq04_dispatched'] is False
            and verdict['claims_consumed'] is False and verdict['source_closure_sha256']==digest(closure)
            and verdict['preflight_sha256']==digest(preflight) and verdict['original']==closure['original_binding'],
            'prior complete gate admission')
    require(window['schema']=='task13_readonly_gate_window_v1'
            and window['deadline_mono_ns']-window['created_mono_ns']==1200*10**9
            and (instant(window['expires_utc'])-instant(window['created_utc'])).total_seconds()==1200,'prior observation window')
    require(controller['pid']==window['controller']['pid'] and controller['birth']==window['controller']['birth']
            and controller['wait_result']==0 and controller['exit_code']==0 and controller['seq04_dispatched'] is False,
            'prior read-only native completion')
    from .receipt import raw_bytes
    stdout,stderr=raw_bytes(controller['stdout_b64']),raw_bytes(controller['stderr_b64'])
    require(stderr==b'' and sha256(stdout)==controller['stdout_sha256'] and sha256(stderr)==controller['stderr_sha256']
            and parse_json(stdout.strip())==verdict,'prior controller raw verdict')
    require(instant(window['created_utc'])<=instant(preflight['finished_utc'])<=instant(verdict['checked_utc'])
            <=instant(controller['finished_utc'])<=instant(window['expires_utc']),'prior gate chronology')
    state=observation(preflight,window,maximum=60)
    if prefix is not None:
        require(verdict['original']==prefix.binding,'prior gate belongs to another prefix')
        validate_state(prefix,window,state,preflight['finished_utc'])
    return dict(schema='task13_prior_gate_admission_v1',status='PRIOR_READONLY_GATE_VERIFIED',source_root=str(root),
        files_sha256=dict(PINS),original=verdict['original'],preflight_sha256=digest(preflight),checked_utc=verdict['checked_utc'])


def hold_gate(stack,expected,prefix):
    root=Path.home()/'.codex/task-evidence'/ROOT_NAME
    for path in reversed((root,*root.parents)):
        stack.enter_context(windows.retained(path,directory=True,protected=path==root,security=path==root))
    stack.enter_context(windows.retained(root/'read-only-guard',directory=True,protected=True))
    for name,pin in PINS.items():
        path=root/name
        handle=stack.enter_context(windows.retained(path,protected=True))
        require(sha256(windows.read_handle(handle,path))==pin,'held prior gate changed')
    require(capture_gate(prefix)==expected,'prior read-only admission changed')
