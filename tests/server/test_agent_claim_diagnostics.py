"""Privacy-preserving diagnosis for unrecognized agent install claims."""

from endpoint_server.enrollment.agent_routes import _claim_identifier


def test_claim_identifier_accepts_only_the_public_install_claim_prefix() -> None:
    """Accepting a bearer secret here could leak it through diagnostic queries."""
    assert _claim_identifier("ic_0123456789abcdef0123456789abcdef.any-secret") == (
        "0123456789abcdef0123456789abcdef"
    )
    assert _claim_identifier("ic_short.any-secret") is None
    assert _claim_identifier("ec_0123456789abcdef0123456789abcdef.any-secret") is None
    assert _claim_identifier("ic_0123456789abcdef0123456789abcdef") is None
