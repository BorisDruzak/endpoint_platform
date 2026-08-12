"""Privacy-preserving diagnosis for unrecognized agent install claims."""

from datetime import UTC, datetime
from uuid import uuid4

from endpoint_server.enrollment.agent_routes import _claim_identifier
from endpoint_server.enrollment.campaigns import _claim_lookup_denial_reason
from endpoint_server.db.models import EnrollmentClaim


def test_claim_identifier_accepts_only_the_public_install_claim_prefix() -> None:
    """Accepting a bearer secret here could leak it through diagnostic queries."""
    assert _claim_identifier("ic_0123456789abcdef0123456789abcdef.any-secret") == (
        "0123456789abcdef0123456789abcdef"
    )
    assert _claim_identifier("ic_short.any-secret") is None
    assert _claim_identifier("ec_0123456789abcdef0123456789abcdef.any-secret") is None
    assert _claim_identifier("ic_0123456789abcdef0123456789abcdef") is None


def test_claim_lookup_diagnostic_distinguishes_absence_from_prior_use() -> None:
    """Collapsing these states would hide whether the agent sent the wrong bearer."""
    claim = EnrollmentClaim(
        id=uuid4(),
        campaign_id=uuid4(),
        claim_identifier="0123456789abcdef0123456789abcdef",
        claim_digest="digest",
        installation_session_digest="session",
        fingerprint_digest="fingerprint",
        expires_at=datetime.now(UTC),
        device_id=None,
        claimed_at=None,
    )

    assert _claim_lookup_denial_reason(None) == "record_absent"
    assert _claim_lookup_denial_reason(claim) is None
    claim.claimed_at = datetime.now(UTC)
    assert _claim_lookup_denial_reason(claim) == "already_claimed"
