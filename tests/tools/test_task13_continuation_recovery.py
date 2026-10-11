"""Recovery admission uses retained actual failure; never grants live acceptance."""
import copy
import os,subprocess,sys,json
from contextlib import ExitStack
from types import SimpleNamespace
from pathlib import Path
import pytest
from tools.canary.task13_continuation.codec import parse_json
from tools.canary.task13_continuation.storage import ProtectedStore

@pytest.fixture(scope='module')
def failed():
    from tools.canary.task13_continuation.recovery import PRIOR_NAME, EVIDENCE
    root=Path.home()/'.codex/task-evidence'/PRIOR_NAME
    if os.name!='nt' or not root.is_dir():pytest.skip('actual protected retained operator failure unavailable')
    store=ProtectedStore(root)
    blobs={name:store.read(name) for name in EVIDENCE}
    binding=parse_json(blobs['control.json'])['original_binding']
    return blobs,{p.name for p in store.root.iterdir()},binding

def test_actual_preflight_unknown_admits_recovery_not_acceptance(failed):
    from tools.canary.task13_continuation.recovery import validate_previous
    blobs,names,binding=failed
    validate_previous(blobs,names,binding,False,True)
    assert any(r['present'] for r in parse_json(blobs['transport-005-current-result.json'])['observation']['known'])

@pytest.mark.parametrize('stage',['dispatch-claim.json','preflight.json','unknown.json','root-completion.json',
                                'transport-006-prepare-intent.json','receipt-04-compare-after-start.json'])
def test_any_later_phase_refuses(failed,stage):
    from tools.canary.task13_continuation.recovery import validate_previous
    blobs,names,binding=failed
    with pytest.raises(ValueError):validate_previous(blobs,names|{stage},binding,False,True)

def test_global_original_claim_refuses(failed):
    from tools.canary.task13_continuation.recovery import validate_previous
    with pytest.raises(ValueError):validate_previous(*failed,True,True)

@pytest.mark.parametrize('field,value',[('wait_result',258),('exit_code',0),('timed_out',True),
                                      ('streams_complete',False),('birth',1),('stdout_sha256','0'*64)])
def test_bad_native_terminal_or_streams_refuse(failed,field,value):
    from tools.canary.task13_continuation.recovery import validate_previous
    from tools.canary.task13_continuation.codec import canonical
    blobs,names,binding=failed;blobs=copy.copy(blobs)
    root=parse_json(blobs['root-transport.json']);root[field]=value
    blobs['root-transport.json']=canonical(root)
    with pytest.raises(ValueError):validate_previous(blobs,names,binding,False,True)

def test_launcher_terminal_alone_does_not_prove_creator_exit(failed):
    from tools.canary.task13_continuation.recovery import validate_previous
    with pytest.raises(ValueError):validate_previous(*failed,False)

def test_changed_reviewed_recovery_evidence_refuses_before_launch(failed,tmp_path):
    from tools.canary.task13_continuation.recovery import capture_recovery,hold_recovery
    blobs,_,binding=failed
    original=SimpleNamespace(root=Path(parse_json(blobs['control.json'])['original_root']),binding=binding)
    # The actual later launch consumed its permanent claim. Do not remove it or
    # borrow its owner to make this pre-launch fixture admissible.
    with pytest.raises(ValueError,match='single recovery launch already consumed'):
        capture_recovery(original)
    prefix=SimpleNamespace(root=ProtectedStore.create_root(tmp_path/'owned-prefix').root,binding=binding)
    record=capture_recovery(prefix)
    assert record['creator_termination_observation']['disposition'] in ('ABSENT','PID_REUSED','EXACT_PROCESS_EXITED')
    record['files']['root-transport.json']['sha256']='0'*64
    with ExitStack() as held,pytest.raises(ValueError):hold_recovery(held,record,prefix,None)

def test_latest_recovery_human_scope_is_required():
    from tools.canary.task13_continuation.permission import REQUEST
    assert REQUEST.startswith('Task 13 — PID Identity Guard Correction\n')
    assert 'Seq 04 запускать отдельным шагом, только если весь continuation gate подтверждён.' in REQUEST
    assert 'Для `sshd.exe` никакого вмешательства в службу не требуется.' in REQUEST

@pytest.mark.skipif(os.name!='nt',reason='native shared exclusive recovery claim')
def test_one_recovery_launch_across_different_continuation_ids(tmp_path,failed):
    from tools.canary.task13_continuation.recovery import claim_recovery_launch,check_recovery_launch,launch_owner
    from uuid import uuid4
    root=ProtectedStore.create_root(tmp_path/'owned-prefix').root
    prefix=SimpleNamespace(root=root,binding=failed[2])
    first={'continuation_id':str(uuid4())};second={'continuation_id':str(uuid4())}
    check_recovery_launch(prefix,None,False)
    with pytest.raises(ValueError):check_recovery_launch(prefix,launch_owner(prefix,first),True)
    claim_recovery_launch(prefix,first)
    check_recovery_launch(prefix,launch_owner(prefix,first),True)
    with pytest.raises(ValueError):check_recovery_launch(prefix,None,False)
    with pytest.raises(ValueError):check_recovery_launch(prefix,launch_owner(prefix,second),False)
    with pytest.raises(OSError):claim_recovery_launch(prefix,second)

@pytest.mark.skipif(os.name!='nt',reason='native owned process identity')
def test_live_exact_process_refuses_termination_proof():
    from tools.canary.task13_continuation import windows
    identity=windows.observe_controller()
    with pytest.raises(ValueError):windows.confirm_process_gone(identity['pid'],identity['birth'])

@pytest.mark.skipif(os.name!='nt',reason='native direct interpreter supervision')
def test_direct_base_interpreter_handle_binds_actual_creator():
    from tools.canary.task13_continuation import windows
    root=Path(__file__).resolve().parents[2]
    source=('import sys,json;sys.path.insert(0,'+repr(str(root))+');'
            'from tools.canary.task13_continuation import windows;'
            'print(json.dumps(windows.observe_controller()),flush=True);sys.stdin.buffer.read(1)')
    process=subprocess.Popen([sys._base_executable,'-I','-S','-B','-c',source],
                             stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=0x08000000)
    try:
        identity=json.loads(process.stdout.readline())
        assert identity['pid']==process.pid
        assert identity['birth']==windows.process_birth(process._handle)
        with pytest.raises(ValueError):windows.confirm_process_gone(identity['pid'],identity['birth'])
        stdout,stderr=process.communicate(b'x',timeout=10)
        assert stdout==stderr==b'' and process.returncode==0
        assert windows.retained_process_exit(process._handle)['birth']==identity['birth']
        assert windows.confirm_process_gone(identity['pid'],identity['birth'])=='EXACT_PROCESS_EXITED'
    finally:
        if process.poll() is None:process.kill();process.communicate(timeout=5)
