"""Agent enrollment, delivery retry, and credential-rotation API tests."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_server.config import Settings
from endpoint_server.db.models import (
    AuditEvent,
    Device,
    DeviceCredential,
    EnrollmentCampaign,
    EnrollmentClaim,
    EnrollmentEvent,
    EnrollmentRetryEnvelope,
)
from endpoint_server.enrollment.campaigns import issue_campaign, issue_install_claim
from endpoint_server.enrollment.credentials import device_token_matches
from endpoint_server.main import create_app


NOW = datetime.now(UTC)
PEPPER = b"agent-enrollment-device-pepper-for-testing"


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=PEPPER,
        service_token_pepper=b"service-token-pepper",
        session_secret=b"session-secret-for-retry-envelope",
        allowed_agent_cidrs=(ip_network("192.168.100.0/24"),),
        allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )


class _Result:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value

    def scalar(self) -> object | None:
        return self.value


class _AgentEnrollmentSession:
    def __init__(
        self,
        *,
        campaign: EnrollmentCampaign,
        claim: EnrollmentClaim | None = None,
        fail_audit: bool = False,
    ) -> None:
        self.campaign = campaign
        self.claim = claim
        self.fail_audit = fail_audit
        self.added: list[object] = []
        self.deleted: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    def add(self, value: object) -> None:
        if self.fail_audit and isinstance(value, AuditEvent):
            raise RuntimeError("injected audit failure")
        self.added.append(value)

    def add_all(self, values: tuple[object, ...]) -> None:
        for value in values:
            self.add(value)

    async def execute(self, statement: object) -> _Result:
        descriptions = getattr(statement, "column_descriptions", ())
        entity = descriptions[0].get("entity") if descriptions else None
        if entity is EnrollmentCampaign:
            return _Result(self.campaign)
        if entity is EnrollmentClaim:
            return _Result(self.claim)
        if entity is Device:
            return _Result(
                next(
                    (value for value in self.added if isinstance(value, Device)),
                    None,
                )
            )
        if entity is DeviceCredential:
            return _Result(
                next(
                    (
                        value
                        for value in self.added
                        if isinstance(value, DeviceCredential)
                    ),
                    None,
                )
            )
        if entity is EnrollmentRetryEnvelope:
            return _Result(
                next(
                    (
                        value
                        for value in self.added
                        if isinstance(value, EnrollmentRetryEnvelope)
                        and value not in self.deleted
                    ),
                    None,
                )
            )
        if entity is EnrollmentEvent:
            return _Result(
                next(
                    (
                        value
                        for value in self.added
                        if isinstance(value, EnrollmentEvent)
                    ),
                    None,
                )
            )
        return _Result(None)

    async def delete(self, value: object) -> None:
        self.deleted.append(value)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1


class _Provider:
    def __init__(self, session: _AgentEnrollmentSession) -> None:
        self.session = session

    @asynccontextmanager
    async def __call__(self):
        yield self.session


def _campaign() -> tuple[str, EnrollmentCampaign]:
    issued = issue_campaign(
        PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=2,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={"policy_id": "linux-stable", "channel": "stable"},
        label="Office Linux",
        now=NOW,
    )
    return issued.token, issued.record


def _claim() -> tuple[str, EnrollmentCampaign, EnrollmentClaim]:
    _, campaign = _campaign()
    issued = issue_install_claim(
        campaign,
        PEPPER,
        installation_session="installation-session-a",
        hardware_fingerprint="sha256:agent-device-a",
        expires_at=NOW + timedelta(minutes=10),
        now=NOW,
    )
    return issued.token, campaign, issued.record


def _enrollment_body() -> dict[str, str]:
    return {
        "schema_version": "enrollment_request_v1",
        "platform": "linux",
        "hardware_fingerprint": "sha256:agent-device-a",
        "installation_id": "installation-session-a",
        "requested_at": NOW.isoformat(),
    }


@pytest.mark.asyncio
async def test_campaign_enrollment_returns_show_once_delivery_and_audits_atomically() -> (
    None
):
    """Missing device creation, token delivery, or audit must break enrolment."""
    campaign_token, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/agent/v1/enroll",
            headers={
                "Authorization": f"Bearer {campaign_token}",
                "X-Request-ID": "agent-enroll-a",
            },
            json=_enrollment_body(),
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["schema_version"] == "enrollment_response_v1"
    assert payload["policy_id"] == "linux-stable"
    assert payload["policy"] == {
        "policy_id": "linux-stable",
        "channel": "stable",
    }
    assert payload["device_token"]
    assert payload["enrollment_receipt"]
    device = next(value for value in session.added if isinstance(value, Device))
    credential = next(
        value for value in session.added if isinstance(value, DeviceCredential)
    )
    envelope = next(
        value for value in session.added if isinstance(value, EnrollmentRetryEnvelope)
    )
    assert payload["device_id"] == str(device.id)
    assert payload["device_token"] not in repr(credential)
    assert payload["device_token"].encode() not in envelope.encrypted_token
    assert payload["enrollment_receipt"] not in repr(envelope)
    assert campaign.use_count == 1
    actions = [value.action for value in session.added if isinstance(value, AuditEvent)]
    assert actions == [
        "enrollment_campaign.use_reserved",
        "device.enrolled",
    ]
    assert session.commit_calls == 1
    assert session.rollback_calls == 0


@pytest.mark.asyncio
async def test_install_claim_enrollment_consumes_claim_once_and_links_device() -> None:
    """Skipping claim bindings or device linkage would permit credential reuse."""
    claim_token, campaign, claim = _claim()
    session = _AgentEnrollmentSession(campaign=campaign, claim=claim)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {claim_token}"},
            json=_enrollment_body(),
        )

    assert response.status_code == 201
    device = next(value for value in session.added if isinstance(value, Device))
    assert claim.claimed_at is not None
    assert claim.device_id == device.id
    assert campaign.use_count == 1
    actions = [value.action for value in session.added if isinstance(value, AuditEvent)]
    assert actions == ["enrollment_claim.consumed", "device.enrolled"]


@pytest.mark.asyncio
async def test_duplicate_enrollment_is_conflict_without_second_device_or_quota_use() -> (
    None
):
    """Retrying the initial POST must never create a second identity or consume quota."""
    campaign_token, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        first = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )
        persisted_count = len(session.added)
        duplicate = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )

    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Enrollment already completed"}
    assert len(session.added) == persisted_count
    assert campaign.use_count == 1
    assert len([value for value in session.added if isinstance(value, Device)]) == 1


@pytest.mark.asyncio
async def test_duplicate_claim_enrollment_keeps_original_claim_and_quota() -> None:
    """Omitting claim attribution would turn a harmless duplicate into a second use."""
    claim_token, campaign, claim = _claim()
    session = _AgentEnrollmentSession(campaign=campaign, claim=claim)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        first = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {claim_token}"},
            json=_enrollment_body(),
        )
        duplicate = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {claim_token}"},
            json=_enrollment_body(),
        )

    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert campaign.use_count == 1
    event = next(value for value in session.added if isinstance(value, EnrollmentEvent))
    assert event.claim_id == claim.id


@pytest.mark.asyncio
async def test_duplicate_requires_original_platform_and_campaign_source_context() -> (
    None
):
    """A changed platform or source CIDR must not be mistaken for idempotent replay."""
    campaign_token, campaign = _campaign()
    campaign.allowed_cidrs = ["192.168.100.0/25"]
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        first = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )
        changed_platform_body = _enrollment_body()
        changed_platform_body["platform"] = "windows"
        changed_platform = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=changed_platform_body,
        )

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.200", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        changed_source = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )

    assert first.status_code == 201
    assert changed_platform.status_code == changed_source.status_code == 403
    assert (
        changed_platform.json()
        == changed_source.json()
        == {"detail": "Enrollment denied"}
    )
    assert campaign.use_count == 1


@pytest.mark.asyncio
async def test_retry_replays_delivery_until_ack_then_fails_closed() -> None:
    """Deleting before ack or retaining after ack would break retry-safe delivery."""
    campaign_token, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        enrolled = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )
        delivery = enrolled.json()
        retry_body = {
            "receipt": delivery["enrollment_receipt"],
            "hardware_fingerprint": "sha256:agent-device-a",
        }
        retry_a = await client.post("/agent/v1/enroll/retry", json=retry_body)
        retry_b = await client.post("/agent/v1/enroll/retry", json=retry_body)
        acknowledged = await client.post("/agent/v1/enroll/ack", json=retry_body)
        replay_after_ack = await client.post(
            "/agent/v1/enroll/retry",
            json=retry_body,
        )

    assert retry_a.status_code == retry_b.status_code == 200
    assert retry_a.json() == retry_b.json() == delivery
    assert acknowledged.status_code == 204
    assert replay_after_ack.status_code == 403
    assert replay_after_ack.json() == {"detail": "Enrollment delivery unavailable"}
    envelope = next(
        value for value in session.added if isinstance(value, EnrollmentRetryEnvelope)
    )
    assert session.deleted == [envelope]
    actions = [value.action for value in session.added if isinstance(value, AuditEvent)]
    assert actions[-1] == "enrollment.delivery_acknowledged"


@pytest.mark.asyncio
async def test_retry_expiry_and_fingerprint_mismatch_hide_secret_inputs() -> None:
    """Expired or stolen receipts must fail identically without reflecting secrets."""
    campaign_token, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        enrolled = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )
        delivery = enrolled.json()
        mismatch_marker = "sha256:stolen-fingerprint-marker"
        mismatch = await client.post(
            "/agent/v1/enroll/retry",
            json={
                "receipt": delivery["enrollment_receipt"],
                "hardware_fingerprint": mismatch_marker,
            },
        )
        envelope = next(
            value
            for value in session.added
            if isinstance(value, EnrollmentRetryEnvelope)
        )
        envelope.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        expired = await client.post(
            "/agent/v1/enroll/retry",
            json={
                "receipt": delivery["enrollment_receipt"],
                "hardware_fingerprint": "sha256:agent-device-a",
            },
        )

    assert mismatch.status_code == expired.status_code == 403
    assert (
        mismatch.json()
        == expired.json()
        == {"detail": "Enrollment delivery unavailable"}
    )
    assert mismatch_marker not in mismatch.text
    assert delivery["enrollment_receipt"] not in mismatch.text


@pytest.mark.asyncio
async def test_rotation_requires_old_token_and_activation_retires_it_immediately() -> (
    None
):
    """Accepting the old token after activation would defeat credential rotation."""
    campaign_token, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        enrolled = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )
        old_token = enrolled.json()["device_token"]
        rotated = await client.post(
            "/agent/v1/credentials/rotate",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        pending_token = rotated.json()["device_token"]
        activated = await client.post(
            "/agent/v1/credentials/activate",
            headers={"Authorization": f"Bearer {pending_token}"},
        )
        old_reuse = await client.post(
            "/agent/v1/credentials/rotate",
            headers={"Authorization": f"Bearer {old_token}"},
        )

    assert rotated.status_code == 201
    assert rotated.json()["overlap_expires_at"]
    assert activated.status_code == 204
    assert old_reuse.status_code == 401
    credential = next(
        value for value in session.added if isinstance(value, DeviceCredential)
    )
    assert device_token_matches(pending_token, credential.token_digest, PEPPER)
    assert credential.pending_token_digest is None
    assert credential.rotation_overlap_expires_at is None
    actions = [value.action for value in session.added if isinstance(value, AuditEvent)]
    assert actions[-2:] == [
        "device_credential.rotation_started",
        "device_credential.rotation_activated",
    ]


@pytest.mark.asyncio
async def test_rotation_old_token_expires_at_overlap_deadline() -> None:
    """The old bearer must stop authorizing mutations at the overlap boundary."""
    campaign_token, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        enrolled = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )
        old_token = enrolled.json()["device_token"]
        rotated = await client.post(
            "/agent/v1/credentials/rotate",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        credential = next(
            value for value in session.added if isinstance(value, DeviceCredential)
        )
        credential.rotation_overlap_expires_at = datetime.now(UTC)
        after_deadline = await client.post(
            "/agent/v1/credentials/rotate",
            headers={"Authorization": f"Bearer {old_token}"},
        )

    assert rotated.status_code == 201
    assert after_deadline.status_code == 401
    assert after_deadline.json() == {"detail": "Invalid device credential"}


@pytest.mark.asyncio
async def test_rotation_missing_bearer_uses_generic_credential_denial() -> None:
    """Malformed authentication must not expose enrollment-specific state."""
    _, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post("/agent/v1/credentials/rotate")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid device credential"}


@pytest.mark.asyncio
async def test_enrollment_rolls_back_when_device_audit_append_fails() -> None:
    """A device identity may not commit when its required audit event cannot append."""
    campaign_token, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign, fail_audit=True)
    app = create_app(_settings(), session_provider=_Provider(session))

    with pytest.raises(RuntimeError, match="injected audit failure"):
        async with AsyncClient(
            transport=ASGITransport(
                app=app,
                client=("192.168.100.20", 43100),
            ),
            base_url="https://endpoint.sosnadmin.local",
        ) as client:
            await client.post(
                "/agent/v1/enroll",
                headers={"Authorization": f"Bearer {campaign_token}"},
                json=_enrollment_body(),
            )

    assert session.commit_calls == 0
    assert session.rollback_calls == 1


@pytest.mark.asyncio
async def test_enrollment_uses_observed_peer_and_ignores_forwarded_address() -> None:
    """Trusting a caller-controlled forwarding header would bypass campaign CIDRs."""
    campaign_token, campaign = _campaign()
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("203.0.113.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/agent/v1/enroll",
            headers={
                "Authorization": f"Bearer {campaign_token}",
                "X-Forwarded-For": "192.168.100.20",
            },
            json=_enrollment_body(),
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "Enrollment denied"}
    assert campaign.use_count == 0
    assert session.added == []
    assert session.commit_calls == 0


@pytest.mark.asyncio
async def test_unbounded_policy_identifier_falls_back_to_campaign_identifier() -> None:
    """Control characters in administrator policy must not become protocol identity."""
    campaign_token, campaign = _campaign()
    campaign.policy["policy_id"] = "unsafe\npolicy-marker"
    session = _AgentEnrollmentSession(campaign=campaign)
    app = create_app(_settings(), session_provider=_Provider(session))

    async with AsyncClient(
        transport=ASGITransport(
            app=app,
            client=("192.168.100.20", 43100),
        ),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/agent/v1/enroll",
            headers={"Authorization": f"Bearer {campaign_token}"},
            json=_enrollment_body(),
        )

    assert response.status_code == 201
    assert response.json()["policy_id"] == campaign.campaign_identifier
