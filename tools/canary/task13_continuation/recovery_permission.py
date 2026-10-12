"""New exact human execution scope; ordinary permission parser is unchanged."""
import os
from datetime import datetime,timezone,timedelta
from pathlib import Path

from .codec import canonical,digest,hex256,instant,parse_json,require,sha256,uuid

PREFIX='TASK13_RECOVERY_EXECUTE_V1 '
FIELDS={'gate_sha256','implementation_sha','protocol_source_sha256','continuation_id','allowed_seq','expires_utc'}

def _latest_actual_message():
    thread=uuid(os.environ.get('CODEX_THREAD_ID'))
    paths=list((Path.home()/'.codex/sessions').glob('*/*/*/rollout-*'+thread+'.jsonl'))
    require(len(paths)==1,'one actual app session required')
    path=paths[0];stat=path.lstat()
    require(not path.is_symlink() and not getattr(stat,'st_file_attributes',0)&0x400
        and stat.st_nlink==1 and stat.st_size<64*1024*1024,'actual operator session identity')
    raw=path.read_bytes();require(len(raw)<64*1024*1024,'operator session bound')
    frames=raw.splitlines();require(frames and parse_json(frames[0])['payload']['id']==thread,'actual session identity')
    latest=None
    for index,line in enumerate(frames):
        try:frame=parse_json(line)
        except ValueError:
            require(index==len(frames)-1 and not raw.endswith(b'\n'),'corrupt complete app frame');continue
        payload=frame.get('payload',{})
        if frame.get('type')=='response_item' and payload.get('type')=='message' and payload.get('role')=='user':
            text=''.join(r.get('text','') for r in payload.get('content',[]) if r.get('type')=='input_text')
            latest=(text,line,frame)
    require(latest is not None,'actual human execution authorization missing')
    return thread,path,latest

def capture_recovery_permission(gate):
    require(gate.get('schema')=='task13_additive_recovery_gate_v1'
        and gate.get('status')=='READY_REQUIRES_SEPARATE_AUTHORIZATION'
        and type(gate.get('allowed_seq')) is int and gate['allowed_seq']==4
        and gate.get('seq04_authorized') is False,'read-only recovery gate required')
    thread,path,(text,line,frame)=_latest_actual_message()
    require(text.startswith(PREFIX),'separate actual recovery execution authorization required')
    fields=parse_json(text[len(PREFIX):].encode('utf-8'))
    require(type(fields) is dict and set(fields)==FIELDS and text==PREFIX+canonical(fields).decode('ascii'),
        'exact canonical recovery authorization; no caller quote')
    require(type(fields['allowed_seq']) is int and fields['allowed_seq']==4
        and fields['gate_sha256']==digest(gate)
        and fields['implementation_sha']==gate['implementation_sha']
        and fields['protocol_source_sha256']==gate['protocol_source_sha256']
        and fields['continuation_id']==gate['continuation_id'],'recovery gate/source/identity authorization binding')
    hex256(fields['gate_sha256']);hex256(fields['protocol_source_sha256']);uuid(fields['continuation_id'])
    require(type(fields['implementation_sha']) is str and len(fields['implementation_sha'])==40
        and all(c in '0123456789abcdef' for c in fields['implementation_sha']),'exact recovery implementation revision')
    now=datetime.now(timezone.utc);end=instant(fields['expires_utc']);checked=instant(gate['checked_utc'])
    require(checked<=now<end<=checked+timedelta(seconds=1200),'recovery authorization expired or unbounded')
    return dict(schema='task13_actual_recovery_execution_request_v1',scope='seq04-additive-recovery-v1',
        **fields,thread_id=thread,source=str(path),record_sha256=sha256(line),record=frame)

def verify_recovery_permission(expected,gate):
    require(expected.get('schema')=='task13_actual_recovery_execution_request_v1'
        and expected.get('scope')=='seq04-additive-recovery-v1','separate actual recovery execution authorization required')
    require(expected==capture_recovery_permission(gate),'recovery authorization changed or replayed')

def authorization_template(gate,expires_utc):
    """Text only; this helper creates no authorization, claims or execution state."""
    return PREFIX+canonical(dict(gate_sha256=digest(gate),implementation_sha=gate['implementation_sha'],
        protocol_source_sha256=gate['protocol_source_sha256'],continuation_id=gate['continuation_id'],
        allowed_seq=4,expires_utc=expires_utc)).decode('ascii')
