"""Admission to the separately reviewed seq04 step after the real read-only gate."""
import os
import pytest

pytestmark=[pytest.mark.no_db,pytest.mark.skipif(not os.environ.get('TASK13_HISTORICAL_ROOT'),reason='private retained gate')]

@pytest.fixture(scope='module')
def prefix():
    from tools.canary.task13_continuation.history import verify_historical_prefix
    return verify_historical_prefix(os.environ['TASK13_HISTORICAL_ROOT'])

def test_actual_prior_gate_is_admission_only_and_does_not_dispatch(prefix):
    from tools.canary.task13_continuation.gate_admission import capture_gate
    proof=capture_gate(prefix)
    assert proof['status']=='PRIOR_READONLY_GATE_VERIFIED'
    assert proof['original']==prefix.binding and len(proof['files_sha256'])==8

def test_other_prefix_cannot_borrow_prior_gate(prefix):
    from types import SimpleNamespace
    from tools.canary.task13_continuation.gate_admission import capture_gate
    other=SimpleNamespace(root=prefix.root,plan=prefix.plan,binding=dict(prefix.binding,original_tip='0'*64),controller=prefix.controller)
    with pytest.raises(ValueError):capture_gate(other)

def test_caller_quote_cannot_turn_guard_scope_into_execution():
    from tools.canary.task13_continuation.permission import capture_permission,verify_permission
    permission=capture_permission()
    permission['scope']='seq04-execution'
    with pytest.raises(ValueError):verify_permission(permission)

@pytest.mark.parametrize('name',['closure.json','review.json','trust.json','operator-request.json','observation-controller.json','window.json','preflight.json','verdict.json'])
def test_changed_pinned_gate_refuses_without_changing_saved_evidence(prefix,monkeypatch,name):
    from tools.canary.task13_continuation.gate_admission import capture_gate
    from tools.canary.task13_continuation.storage import ProtectedStore
    read=ProtectedStore.read
    def changed(self,filename):
        raw=read(self,filename)
        return raw+b' ' if filename==name else raw
    monkeypatch.setattr(ProtectedStore,'read',changed)
    with pytest.raises(ValueError,match='pin changed'):capture_gate(prefix)

def test_changed_admission_is_rejected_under_native_retained_handles(prefix):
    from contextlib import ExitStack
    from tools.canary.task13_continuation.gate_admission import capture_gate,hold_gate
    proof=capture_gate(prefix);proof['preflight_sha256']='0'*64
    with ExitStack() as held,pytest.raises(ValueError,match='admission changed'):
        hold_gate(held,proof,prefix)

def test_separate_permission_binds_actual_message_and_prior_gate(prefix):
    from tools.canary.task13_continuation.permission import capture_execution_permission,verify_permission
    from tools.canary.task13_continuation.gate_admission import capture_gate
    from tools.canary.task13_continuation.codec import digest
    permission=capture_execution_permission(prefix)
    assert permission['scope']=='seq04-execution' and permission['gate_admission_sha256']==digest(capture_gate(prefix))
    verify_permission(permission)
