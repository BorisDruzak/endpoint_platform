"""Owned synthetic orchestration tests; no target contacts or execution authority."""
import os
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from tools.canary.task13_continuation.codec import canonical,parse_json

pytestmark=pytest.mark.no_db

@pytest.mark.skipif(os.name!='nt',reason='owned protected native store')
@pytest.mark.parametrize('entry',['--execute-reviewed-seq04','--execute-reviewed-seq04-child'])
def test_guard_only_permission_refuses_before_any_execution_mutation(tmp_path,monkeypatch,entry):
    from tools.canary.task13_continuation import loader,supervisor
    from tools.canary.task13_continuation.storage import ProtectedStore
    store=ProtectedStore.create_root(tmp_path/'guard')
    @contextmanager
    def bundle(*args):
        yield store,{}, {}, {}, {}, None,{'scope':'pid-identity-readonly-guard'}, {}, {}
    monkeypatch.setattr(loader,'reviewed_bundle',bundle)
    monkeypatch.setattr(supervisor,'reviewed_bundle',bundle)
    monkeypatch.setattr(sys,'argv',[str(store.root/'bootstrap.py'),entry])
    with pytest.raises(ValueError,match='separate seq04 step'):
        if entry.endswith('-child'):loader.run_seq04({'bootstrap_root':str(store.root)},None)
        else:supervisor.supervise(store.root)
    assert list(store.root.iterdir())==[]

@pytest.mark.skipif(os.name!='nt',reason='owned protected native store')
@pytest.mark.parametrize('success',[True,False])
def test_readonly_entry_emits_verdict_without_capsule_workload_or_claim(tmp_path,monkeypatch,success):
    from tools.canary.task13_continuation import loader,readonly_gate
    from tools.canary.task13_continuation.storage import ProtectedStore
    store=ProtectedStore.create_root(tmp_path/'guard')
    identity={'pid':100,'birth':200}
    @contextmanager
    def bundle(*args):
        yield store,{'synthetic':'source-only'}, {}, {'reviewer_controller':{'pid':300,'birth':400}}, {},SimpleNamespace(binding={}),{}, {},{}
    monkeypatch.setattr(loader,'reviewed_bundle',bundle)
    monkeypatch.setattr(readonly_gate.windows,'observe_controller',lambda:identity)
    monkeypatch.setattr(readonly_gate,'verify_permission',lambda *a:None)
    def reconcile(*args):
        args[1].check()
        if not success:raise ValueError('fixed synthetic guard refusal')
        return {'status':'synthetic orchestration only'}
    monkeypatch.setattr(loader,'_reconcile',reconcile)
    monkeypatch.setattr(sys,'argv',[str(store.root/'bootstrap.py'),'--observe-reviewed-guard'])
    result=readonly_gate.observe_reviewed_guard(store.root)
    assert result['status']==('READY_FOR_SEPARATE_SEQ04' if success else 'BLOCKED')
    assert result['claims_consumed'] is False and result['seq04_dispatched'] is False
    assert [p.name for p in store.root.iterdir()]==['read-only-guard']
    names={p.name for p in (store.root/'read-only-guard').iterdir()}
    assert names==({'window.json','verdict.json','preflight.json'} if success else {'window.json','verdict.json'})
    window=parse_json((store.root/'read-only-guard/window.json').read_bytes())
    assert window['schema']=='task13_readonly_gate_window_v1' and 'allowed_seq' not in window
    assert window['deadline_mono_ns']-window['created_mono_ns']==1200*10**9

def test_readonly_window_refuses_changed_identity_and_expired_budget(monkeypatch):
    from tools.canary.task13_continuation import readonly_gate
    identity={'pid':1,'birth':2}
    monkeypatch.setattr(readonly_gate.windows,'observe_controller',lambda:identity)
    window=readonly_gate.ReadOnlyWindow(identity);window.check()
    identity['birth']=3
    with pytest.raises(ValueError,match='controller changed'):window.check()
    identity['birth']=2
    monkeypatch.setattr(readonly_gate.time,'monotonic_ns',lambda:window.capsule['deadline_mono_ns'])
    with pytest.raises(ValueError,match='expired'):window.check()
