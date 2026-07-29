from __future__ import annotations

from pc_agent.context_profiles.diagnostic import DIAGNOSTIC_LOG_BYTES, collect_diagnostic

from .conftest import FIXED_TIME


def test_diagnostic_redacts_sensitive_values_before_truncation(fake_probe) -> None:
    """A bounded diagnostic excerpt never returns a token value from local logs."""
    result = collect_diagnostic(fake_probe, reason="operator investigation", collected_at=FIXED_TIME)

    assert "super-secret" not in (result.sections.log_excerpt or "")
    assert "<redacted>" in (result.sections.log_excerpt or "")
    assert "redaction_applied" in result.warnings


def test_diagnostic_redacts_bearer_credentials_before_truncation(fake_probe) -> None:
    """Bearer credentials are fully removed even when the excerpt ends in the header."""
    secret = "secret-token-value"
    fake_probe.outputs[("journalctl", "-n", "100", "--no-pager", "-o", "cat")] = (
        "x" * (DIAGNOSTIC_LOG_BYTES - 51) + f"\nAuthorization: Bearer {secret}\n"
    )

    result = collect_diagnostic(fake_probe, reason="operator investigation", collected_at=FIXED_TIME)

    assert secret not in (result.sections.log_excerpt or "")
    assert "Authorization: Bearer <redacted>" in (result.sections.log_excerpt or "")
