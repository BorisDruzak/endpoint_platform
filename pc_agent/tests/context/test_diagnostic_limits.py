from __future__ import annotations

from pc_agent.context_profiles.diagnostic import (
    DIAGNOSTIC_LOG_BYTES,
    DIAGNOSTIC_PROCESS_LIMIT,
    collect_diagnostic,
)

from .conftest import FIXED_TIME


def test_diagnostic_is_bounded(fake_probe) -> None:
    """Even an oversized local log and process listing remain contract-sized."""
    fake_probe.outputs[("ps", "-eo", "comm=,stat=")] = "worker S\n" * (DIAGNOSTIC_PROCESS_LIMIT + 10)
    fake_probe.outputs[("journalctl", "-n", "100", "--no-pager", "-o", "cat")] = "entry\n" * (DIAGNOSTIC_LOG_BYTES + 10)

    result = collect_diagnostic(fake_probe, reason="manual check", collected_at=FIXED_TIME)

    assert len(result.sections.processes) <= DIAGNOSTIC_PROCESS_LIMIT
    assert len((result.sections.log_excerpt or "").encode()) <= DIAGNOSTIC_LOG_BYTES
    assert "data_truncated" in result.warnings
