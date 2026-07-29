from __future__ import annotations

from pc_agent.context_profiles.diagnostic import collect_diagnostic

from .conftest import FIXED_TIME


def test_diagnostic_redacts_sensitive_values_before_truncation(fake_probe) -> None:
    """A bounded diagnostic excerpt never returns a token value from local logs."""
    result = collect_diagnostic(fake_probe, reason="operator investigation", collected_at=FIXED_TIME)

    assert "super-secret" not in (result.sections.log_excerpt or "")
    assert "<redacted>" in (result.sections.log_excerpt or "")
    assert "redaction_applied" in result.warnings
