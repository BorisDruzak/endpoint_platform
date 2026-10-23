from __future__ import annotations

import json
import pytest

from pc_agent.context_profiles.probe import JOURNAL_COMMAND
from pc_agent.context_profiles.diagnostic import collect_diagnostic
from .conftest import FIXED_TIME


@pytest.mark.parametrize('secret', [
    'token=super-secret', 'Authorization: Bearer secret-token-value',
    'Authorization =   Bearer secret-equals',
])
def test_diagnostic_discards_messages_cursors_and_private_service_instances(fake_probe, secret):
    fake_probe.outputs[JOURNAL_COMMAND] = json.dumps({
        '__REALTIME_TIMESTAMP':'1785326400000000', 'PRIORITY':'3',
        '_SYSTEMD_UNIT':'worker@private-user.service',
        'MESSAGE':secret, '__CURSOR':'private-cursor', '_CMDLINE':'private-command',
    })
    result=collect_diagnostic(fake_probe, reason='operator investigation', collected_at=FIXED_TIME)
    excerpt=result.sections.log_excerpt
    assert excerpt and 'worker@.service' in excerpt and 'journal_priority_3' in excerpt
    assert secret not in excerpt and 'private-' not in excerpt


def test_diagnostic_rejects_unstructured_log_output(fake_probe):
    fake_probe.outputs[JOURNAL_COMMAND]='token=super-secret\nservice healthy\n'
    result=collect_diagnostic(fake_probe,reason='metadata only',collected_at=FIXED_TIME)
    assert result.sections.log_excerpt is None
    assert 'command_failed' in result.warnings
