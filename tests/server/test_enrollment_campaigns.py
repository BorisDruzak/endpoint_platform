"""Campaign and one-time install-claim behavior."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql

from endpoint_server.audit.redaction import REDACTED, redact_audit_details
from endpoint_server.db.models import EnrollmentCampaign, EnrollmentClaim
from endpoint_server.enrollment.campaigns import (
    EnrollmentDenied,
    campaign_token_digest,
    consume_install_claim,
    issue_campaign,
    issue_install_claim,
    reserve_campaign_use,
    revoke_campaign,
)


NOW = datetime(2026, 7, 29, 10, tzinfo=UTC)
PEPPER = b"campaign-test-pepper-with-enough-entropy"


def _decode_secret(token: str) -> bytes:
    encoded = token.split(".", 1)[1]
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


def test_enrollment_bearer_names_are_redacted_without_hiding_public_ids() -> None:
    """Generic campaign, claim and receipt keys must not bypass audit redaction."""
    assert redact_audit_details(
        {
            "campaign": "raw-campaign",
            "claim": "raw-claim",
            "receipt": "raw-receipt",
            "campaign_id": "public-campaign-id",
            "claim_id": "public-claim-id",
        }
    ) == {
        "campaign": REDACTED,
        "claim": REDACTED,
        "receipt": REDACTED,
        "campaign_id": "public-campaign-id",
        "claim_id": "public-claim-id",
    }


class _Result:
    def __init__(self, value: object | None) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object | None:
        return self._value


class _EnrollmentSession:
    def __init__(
        self,
        *,
        campaign: EnrollmentCampaign | None = None,
        claim: EnrollmentClaim | None = None,
        fail_audit: bool = False,
    ) -> None:
        self.campaign = campaign
        self.claim = claim
        self.fail_audit = fail_audit
        self.added: list[object] = []
        self.statements: list[object] = []

    def add(self, value: object) -> None:
        if self.fail_audit and value.__class__.__name__ == "AuditEvent":
            raise RuntimeError("injected audit failure")
        self.added.append(value)

    async def execute(self, statement: object) -> _Result:
        self.statements.append(statement)
        text = str(
            statement.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": False},
            )
        )
        if "FROM enrollment_claims" in text:
            return _Result(self.claim)
        return _Result(self.campaign)


def test_issue_campaign_returns_32_byte_secret_and_persists_only_digest() -> None:
    """Persisting the raw campaign bearer or issuing short entropy is a credential leak."""
    issued = issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=2,
        allowed_cidrs=("192.168.100.0/24", "2001:db8::/32"),
        target_platform="linux",
        policy={"channel": "stable"},
        label="Office Linux",
        site="hq",
        now=NOW,
    )

    assert len(_decode_secret(issued.token)) == 32
    assert issued.record.token_digest == campaign_token_digest(issued.token, PEPPER)
    assert issued.record.campaign_identifier in issued.token
    assert issued.record.max_uses == 2
    assert issued.record.use_count == 0
    assert issued.record.allowed_cidrs == ["192.168.100.0/24", "2001:db8::/32"]
    assert issued.record.target_platform == "linux"
    assert issued.record.policy == {"channel": "stable"}
    assert issued.token not in repr(issued)
    assert issued.token not in repr(issued.record)
    assert not {
        "token",
        "claim",
        "installation_session",
        "hardware_fingerprint",
    }.intersection(EnrollmentCampaign.__table__.columns.keys())


def test_claim_issuance_rejects_inactive_or_exhausted_campaign() -> None:
    """Issuing a claim from unavailable campaign state would bypass its bounds."""
    campaign = issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=1,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=NOW,
    ).record
    campaign.revoked_at = NOW
    with pytest.raises(EnrollmentDenied):
        issue_install_claim(
            campaign,
            PEPPER,
            installation_session="install-session-a",
            hardware_fingerprint="sha256:device-a",
            expires_at=NOW + timedelta(minutes=10),
            now=NOW,
        )

    campaign.revoked_at = None
    campaign.use_count = campaign.max_uses
    with pytest.raises(EnrollmentDenied):
        issue_install_claim(
            campaign,
            PEPPER,
            installation_session="install-session-a",
            hardware_fingerprint="sha256:device-a",
            expires_at=NOW + timedelta(minutes=10),
            now=NOW,
        )


@pytest.mark.asyncio
async def test_reserve_campaign_use_enforces_bounds_and_locks_before_increment() -> (
    None
):
    """Skipping the row lock or a request bound would oversubscribe or widen a campaign."""
    issued = issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=1,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={"channel": "stable"},
        now=NOW,
    )
    session = _EnrollmentSession(campaign=issued.record)

    reserved = await reserve_campaign_use(
        session,
        issued.token,
        PEPPER,
        source_address=ip_address("192.168.100.20"),
        platform="linux",
        actor_kind="agent",
        actor_identifier=None,
        request_id="reserve-1",
        now=NOW,
    )

    assert reserved is issued.record
    assert issued.record.use_count == 1
    sql = str(session.statements[0].compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE" in sql
    audit = session.added[-1]
    assert audit.action == "enrollment_campaign.use_reserved"
    assert audit.details == {"platform": "linux", "source_address": "192.168.100.20"}

    for source, platform in (
        ("192.168.101.20", "linux"),
        ("192.168.100.20", "windows"),
    ):
        issued.record.use_count = 0
        with pytest.raises(EnrollmentDenied):
            await reserve_campaign_use(
                _EnrollmentSession(campaign=issued.record),
                issued.token,
                PEPPER,
                source_address=ip_address(source),
                platform=platform,
                actor_kind="agent",
                actor_identifier=None,
                request_id="denied",
                now=NOW,
            )

    issued.record.use_count = 1
    with pytest.raises(EnrollmentDenied):
        await reserve_campaign_use(
            _EnrollmentSession(campaign=issued.record),
            issued.token,
            PEPPER,
            source_address=ip_address("192.168.100.20"),
            platform="linux",
            actor_kind="agent",
            actor_identifier=None,
            request_id="exhausted",
            now=NOW,
        )

    issued.record.use_count = 0
    issued.record.expires_at = NOW
    with pytest.raises(EnrollmentDenied):
        await reserve_campaign_use(
            _EnrollmentSession(campaign=issued.record),
            issued.token,
            PEPPER,
            source_address=ip_address("192.168.100.20"),
            platform="linux",
            actor_kind="agent",
            actor_identifier=None,
            request_id="expired",
            now=NOW,
        )


@pytest.mark.asyncio
async def test_revoked_campaign_denies_use_and_revoke_audits_without_secret() -> None:
    """A revoked campaign must fail closed and its audit event must not carry bearer data."""
    issued = issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=1,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=NOW,
    )
    session = _EnrollmentSession(campaign=issued.record)

    await revoke_campaign(
        session,
        issued.record.id,
        actor_identifier=str(uuid4()),
        request_id="revoke-1",
        now=NOW,
    )

    assert issued.record.revoked_at == NOW
    assert session.added[-1].details == {}
    assert issued.token not in repr(session.added[-1].details)
    with pytest.raises(EnrollmentDenied):
        await reserve_campaign_use(
            _EnrollmentSession(campaign=issued.record),
            issued.token,
            PEPPER,
            source_address=ip_address("192.168.100.20"),
            platform="linux",
            actor_kind="agent",
            actor_identifier=None,
            request_id="revoked",
            now=NOW,
        )


@pytest.mark.asyncio
async def test_claim_is_one_time_expiring_and_bound_to_session_and_fingerprint() -> (
    None
):
    """Reusing a claim or changing either binding must never authorize installation."""
    campaign = issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=2,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=NOW,
    ).record
    issued = issue_install_claim(
        campaign,
        PEPPER,
        installation_session="install-session-a",
        hardware_fingerprint="sha256:device-a",
        expires_at=NOW + timedelta(minutes=10),
        now=NOW,
    )
    assert len(_decode_secret(issued.token)) == 32
    assert issued.token not in repr(issued)
    assert issued.record.claim_digest != issued.token
    assert issued.record.installation_session_digest != "install-session-a"
    assert issued.record.fingerprint_digest != "sha256:device-a"
    assert not {
        "token",
        "claim",
        "installation_session",
        "hardware_fingerprint",
    }.intersection(EnrollmentClaim.__table__.columns.keys())

    for install_session, fingerprint in (
        ("install-session-b", "sha256:device-a"),
        ("install-session-a", "sha256:device-b"),
    ):
        with pytest.raises(EnrollmentDenied):
            await consume_install_claim(
                _EnrollmentSession(campaign=campaign, claim=issued.record),
                issued.token,
                PEPPER,
                installation_session=install_session,
                hardware_fingerprint=fingerprint,
                actor_kind="agent",
                actor_identifier=None,
                request_id="claim-denied",
                now=NOW,
            )

    original_fingerprint_digest = issued.record.fingerprint_digest
    issued.record.fingerprint_digest = "\N{SNOWMAN}"
    with pytest.raises(EnrollmentDenied):
        await consume_install_claim(
            _EnrollmentSession(campaign=campaign, claim=issued.record),
            issued.token,
            PEPPER,
            installation_session="install-session-a",
            hardware_fingerprint="sha256:device-a",
            actor_kind="agent",
            actor_identifier=None,
            request_id="claim-corrupt",
            now=NOW,
        )
    issued.record.fingerprint_digest = original_fingerprint_digest

    session = _EnrollmentSession(campaign=campaign, claim=issued.record)
    consumed = await consume_install_claim(
        session,
        issued.token,
        PEPPER,
        installation_session="install-session-a",
        hardware_fingerprint="sha256:device-a",
        actor_kind="agent",
        actor_identifier=None,
        request_id="claim-ok",
        now=NOW,
    )
    assert consumed is issued.record
    assert issued.record.claimed_at == NOW
    assert all(
        "FOR UPDATE" in str(statement.compile(dialect=postgresql.dialect()))
        for statement in session.statements
    )
    assert session.added[-1].details == {}

    with pytest.raises(EnrollmentDenied):
        await consume_install_claim(
            _EnrollmentSession(campaign=campaign, claim=issued.record),
            issued.token,
            PEPPER,
            installation_session="install-session-a",
            hardware_fingerprint="sha256:device-a",
            actor_kind="agent",
            actor_identifier=None,
            request_id="claim-reuse",
            now=NOW,
        )

    issued.record.claimed_at = None
    issued.record.expires_at = NOW
    with pytest.raises(EnrollmentDenied):
        await consume_install_claim(
            _EnrollmentSession(campaign=campaign, claim=issued.record),
            issued.token,
            PEPPER,
            installation_session="install-session-a",
            hardware_fingerprint="sha256:device-a",
            actor_kind="agent",
            actor_identifier=None,
            request_id="claim-expired",
            now=NOW,
        )


@pytest.mark.asyncio
async def test_mutation_is_reverted_by_caller_when_audit_append_fails() -> None:
    """A state mutation without its audit record must not be committed."""
    issued = issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=1,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=NOW,
    )
    session = _EnrollmentSession(campaign=issued.record, fail_audit=True)

    with pytest.raises(RuntimeError, match="injected audit failure"):
        await reserve_campaign_use(
            session,
            issued.token,
            PEPPER,
            source_address=ip_address("192.168.100.20"),
            platform="linux",
            actor_kind="agent",
            actor_identifier=None,
            request_id="audit-failure",
            now=NOW,
        )

    assert issued.record.use_count == 1
    assert session.added == []
