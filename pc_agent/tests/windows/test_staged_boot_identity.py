"""Historical WMI/kernel/event identities cannot release recovery boot gates."""
import pytest
from pc_agent.platform.windows import durable_state, staged_recovery as module
from pc_agent.tests.windows.test_staged_recovery import recovery
from pc_agent.tests.windows.test_staged_update_state import staged, move, native_protected_root

LEGACY=['20261020125508.151071+300','kernel-boot-v1:11111111-1111-4111-8111-111111111111','boot-event-v1:1923:'+'a'*64]

@pytest.mark.parametrize('boot',LEGACY)
def test_legacy_input_never_authorizes_trial_after_owner_loss(recovery,staged,monkeypatch,boot):
    _,paths,binding,cap=recovery
    move(staged,'preparing','prepared');move(staged,'prepared','switching')
    monkeypatch.setattr(module,'_validate_recovery_inputs',lambda *_:{'boot':boot})
    with durable_state.installer_mutation_checkpoints(lambda:None):
        assert module.recover_staged_update(paths,binding.operation_id,capability=cap)=='rollback-required'

@pytest.mark.parametrize('boot',LEGACY)
def test_legacy_reboot_record_stays_blocking(recovery,staged,boot):
    _,paths,binding,_=recovery
    with durable_state.installer_mutation_checkpoints(lambda:None):
        record=module.state.read_staged_update(paths)
        module._write(module._root(paths,binding.operation_id,create=True),'reboot.json',{
            'schema_version':1,'binding_sha256':module._binding_hash(record),'native_exit':3010,'boot':boot})
        assert module.reboot_pending(paths,record)
