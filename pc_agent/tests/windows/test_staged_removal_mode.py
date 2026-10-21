"""Recursive uninstall cleanup may be suppressed only by a bound reverse role."""
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installer_transaction_bridge as bridge
from pc_agent.platform.windows import staged_foundation_rollback as rollback


@pytest.mark.parametrize('role,operation,value,allowed', [
    (None, 'install', '', True), (None, 'uninstall', '', True),
    (None, 'uninstall', '1', False), ('remove', 'uninstall', '1', True),
    ('remove', 'uninstall', '', False), ('remove', 'uninstall', '2', False),
    ('remove', 'install', '1', False), ('control', 'install', '1', False),
    ('unknown', 'uninstall', '1', False),
])
def test_staged_cleanup_mode_requires_exact_authenticated_role(monkeypatch, role, operation, value, allowed):
    cap = {'operation': operation}
    if role is not None:
        cap['staged_rollback'] = {'role': role}
    client = SimpleNamespace(capability=cap, phase='msi-preflight')
    called = []
    def phase(*args, **kwargs):
        called.append(True)
        return {'observed': True}
    monkeypatch.setattr(bridge, '_execute_authorized_phase', phase)
    monkeypatch.setattr(rollback, 'execute_candidate_removal_phase', phase)
    monkeypatch.setattr(rollback, 'execute_rollback_control_phase', phase)
    if allowed:
        assert bridge.execute_authorized_phase(client, object(), staged_removal=value) == {'observed': True}
        assert called == [True]
    else:
        with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
            bridge.execute_authorized_phase(client, object(), staged_removal=value)
        assert called == []
