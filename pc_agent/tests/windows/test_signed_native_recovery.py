import pytest

from pc_agent.platform.windows.signed_native_recovery import _assert_scope, _RecoveryOwner


def test_recovery_scope_rejects_each_changed_binding():
    expected = {'machine': 'm', 'transaction': 't', 'grant': 'g', 'completion': 'c'}
    _assert_scope(expected, dict(expected))
    for field in expected:
        with pytest.raises(ValueError, match='RECOVERY_SCOPE_MISMATCH'):
            _assert_scope(expected, {**expected, field: 'different'})


@pytest.mark.parametrize('phase,result', [
    ('inspect', {'operation_id': 'id', 'observer': 'provisioned', 'users': 'not-required'}),
    ('complete', {'operation_id': 'other', 'observer': 'provisioned', 'users': 'not-required'}),
    ('complete', {'operation_id': 'id', 'result': 'native-settled-for-staged-recovery'}),
])
def test_standalone_owner_rejects_unrelated_completion(phase, result):
    owner = _RecoveryOwner({'transaction_id': 'id'}, lambda: None)
    with pytest.raises(ValueError, match='RECOVERY_SCOPE_MISMATCH'):
        owner.request(phase, result)
