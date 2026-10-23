from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

from endpoint_contracts import AgentCommandV1
from pc_agent.context_profiles.command_execution import execute_context_agent_command

from pc_agent.context_profiles.probe import JOURNAL_COMMAND

from pc_agent.context_profiles.diagnostic import (
    DIAGNOSTIC_LOG_BYTES,
    DIAGNOSTIC_PROCESS_LIMIT,
    collect_diagnostic,
)

from .conftest import FIXED_TIME


def test_diagnostic_is_bounded(fake_probe) -> None:
    """Even an oversized local log and process listing remain contract-sized."""
    fake_probe.outputs[("ps", "-eo", "comm=,stat=")] = "worker S\n" * (DIAGNOSTIC_PROCESS_LIMIT + 10)
    fake_probe.outputs[JOURNAL_COMMAND] = "entry\n" * (DIAGNOSTIC_LOG_BYTES + 10)

    result = collect_diagnostic(fake_probe, reason="manual check", collected_at=FIXED_TIME)

    assert len(result.sections.processes) <= DIAGNOSTIC_PROCESS_LIMIT
    assert len((result.sections.log_excerpt or "").encode()) <= DIAGNOSTIC_LOG_BYTES
    assert "data_truncated" in result.warnings


def test_full_journal_metadata_fits_the_real_gateway_result(fake_probe):
    fake_probe.outputs[JOURNAL_COMMAND] = '\n'.join(json.dumps({
        '__REALTIME_TIMESTAMP': '1785326400000000', 'PRIORITY': '3',
        '_SYSTEMD_UNIT': 'a' * 110 + '.service',
        '__CURSOR': 'private-cursor' * 30,
        'MESSAGE': 'private-document-and-secret',
    }) for _ in range(32))
    command = AgentCommandV1(schema_version='agent_command_v1', command_id=uuid4(),
        device_id=uuid4(), capability='context.diagnostic.collect',
        parameters={'reason':'metadata acceptance'},requested_by_service='endpoint-platform',
        idempotency_key='diagnostic-acceptance-test',created_at=FIXED_TIME,
        deadline_at=FIXED_TIME+timedelta(minutes=1))
    result=execute_context_agent_command(command,probe=fake_probe)
    assert result.status=='succeeded'
    payload=json.dumps(result.result_items)
    assert 'private-cursor' not in payload and 'private-document' not in payload
