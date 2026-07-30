"""Scoped service API tests for show-once ALT installation claims."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import AsyncIterator
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from endpoint_contracts import AgentEnrollmentRequestV1
from endpoint_server.auth.service_tokens import create_service_credential
from endpoint_server.config import Settings
from endpoint_server.db.models import (
    AuditEvent,
    DeviceCredential,
    EnrollmentCampaign,
    EnrollmentClaim,
    ServiceClient,
    ServiceCredential,
)
from endpoint_server.enrollment.campaigns import (
    install_claim_bindings_match,
    issue_campaign,
)
from endpoint_server.main import create_app


NOW = datetime.now(UTC)
DEVICE_PEPPER = b"provisioning-claim-device-pepper"
SERVICE_PEPPER = b"provisioning-claim-service-pepper"
PROVISIONING_SCOPE = "provisioning.install-claims.issue"


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://unused@localhost/unused",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=DEVICE_PEPPER,
        service_token_pepper=SERVICE_PEPPER,
        session_secret=b"provisioning-claim-session-secret",
        allowed_agent_cidrs=(),
        allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
    )


class _Result:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value


class _Session:
    def __init__(
        self,
        *,
        client: ServiceClient,
        credential: ServiceCredential,
        campaign: EnrollmentCampaign | None,
        fail_audit: bool = False,
    ) -> None:
        self.client = client
        self.credential = credential
        self.campaign = campaign
        self.fail_audit = fail_audit
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    async def scalar(self, statement: object) -> object | None:
        entity = statement.column_descriptions[0]["entity"]
        if entity is ServiceCredential:
            return self.credential
        if entity is ServiceClient:
            return self.client
        raise AssertionError(f"unexpected scalar query: {entity}")

    async def execute(self, statement: object) -> _Result:
        return _Result(self.campaign)

    def add(self, value: object) -> None:
        if self.fail_audit and isinstance(value, AuditEvent):
            raise RuntimeError("injected audit failure")
        self.added.append(value)

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1


class _Provider:
    def __init__(self, session: _Session) -> None:
        self.session = session

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[_Session]:
        yield self.session


async def _authorized_session(
    *, scopes: tuple[str, ...], campaign: EnrollmentCampaign | None
) -> tuple[_Session, str]:
    client = ServiceClient(
        id=uuid4(),
        client_identifier=f"alt-provisioner-{uuid4().hex}",
        display_name="ALT provisioning controller",
        disabled_at=None,
    )
    bootstrap = _Session(
        client=client,
        credential=ServiceCredential(
            service_client_id=client.id,
            credential_identifier="bootstrap",
            token_prefix="svc_bootstrap",
            secret_digest="unused",
            scopes=["bootstrap"],
            expires_at=None,
            revoked_at=None,
        ),
        campaign=campaign,
    )
    issued = await create_service_credential(
        bootstrap,
        client.id,
        SERVICE_PEPPER,
        actor_kind="admin",
        actor_identifier="seed-admin",
        request_id="seed-provisioner",
        scopes=scopes,
    )
    return (
        _Session(client=client, credential=issued.record, campaign=campaign),
        issued.token,
    )


def _campaign() -> EnrollmentCampaign:
    return issue_campaign(
        DEVICE_PEPPER,
        expires_at=NOW + timedelta(hours=1),
        max_uses=2,
        allowed_cidrs=("192.168.100.0/24",),
        target_platform="linux",
        policy={},
        now=NOW,
    ).record


@pytest.mark.asyncio
async def test_provisioning_claim_requires_exact_dedicated_service_scope() -> None:
    """Admin sessions and unrelated service grants must never issue install claims."""
    campaign = _campaign()
    session, token = await _authorized_session(
        scopes=("context.collect",), campaign=campaign
    )
    app = create_app(_settings(), session_provider=_Provider(session))
    body = {
        "campaign_id": str(campaign.id),
        "install_session_id": "alt-session-001",
        "hardware_fingerprint": "sha256:alt-hardware-001",
    }
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        denied = await client.post(
            "/api/v1/provisioning/install-claims",
            headers={"Authorization": f"Bearer {token}"},
            json=body,
        )
        anonymous = await client.post("/api/v1/provisioning/install-claims", json=body)

    assert denied.status_code == 403
    assert anonymous.status_code == 401
    assert session.added == []
    assert session.commit_calls == 0


@pytest.mark.asyncio
async def test_scoped_provisioner_gets_bound_claim_and_redacted_audit() -> None:
    """The service response is the only raw claim exposure; audit and DB stay secret-free."""
    campaign = _campaign()
    session, token = await _authorized_session(
        scopes=(PROVISIONING_SCOPE,), campaign=campaign
    )
    app = create_app(_settings(), session_provider=_Provider(session))
    install_session = "alt-session-001"
    submitted_fingerprint = "SHA256:ALT-HARDWARE-001"
    fingerprint = "sha256:alt-hardware-001"
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/v1/provisioning/install-claims",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Request-ID": "provisioning-request-secret-marker",
            },
            json={
                "campaign_id": str(campaign.id),
                "install_session_id": install_session,
                "hardware_fingerprint": submitted_fingerprint,
            },
        )

    assert response.status_code == 201
    payload = response.json()
    assert set(payload) == {"claim", "expires_at", "install_session_id"}
    assert payload["claim"].startswith("ic_")
    assert payload["install_session_id"] == install_session
    assert "device_token" not in payload
    assert "credential" not in response.text
    claim = next(value for value in session.added if isinstance(value, EnrollmentClaim))
    audit = next(value for value in session.added if isinstance(value, AuditEvent))
    assert install_claim_bindings_match(
        claim,
        DEVICE_PEPPER,
        installation_session=install_session,
        hardware_fingerprint=fingerprint,
    )
    enrollment_request = AgentEnrollmentRequestV1.model_validate(
        {
            "schema_version": "agent_enrollment_request_v1",
            "platform": "linux",
            "hardware_fingerprint": submitted_fingerprint,
            "installation_id": install_session,
            "delivery_nonce": "A" * 43,
            "requested_at": NOW,
        }
    )
    assert enrollment_request.hardware_fingerprint == fingerprint
    assert not install_claim_bindings_match(
        claim,
        DEVICE_PEPPER,
        installation_session="different-session",
        hardware_fingerprint=fingerprint,
    )
    assert not install_claim_bindings_match(
        claim,
        DEVICE_PEPPER,
        installation_session=install_session,
        hardware_fingerprint="sha256:different-hardware",
    )
    assert payload["claim"] not in repr(claim)
    assert payload["claim"] not in str(vars(claim))
    assert payload["claim"] not in repr(audit)
    assert install_session not in repr(audit)
    assert fingerprint not in repr(audit)
    assert audit.action == "provisioning_install_claim.issued"
    assert audit.actor_kind == "service"
    assert audit.actor_identifier == str(session.client.id)
    assert audit.details == {
        "campaign_id": str(campaign.id),
        "expires_at": claim.expires_at.isoformat(),
    }
    assert audit.request_id.startswith("external_")
    assert not any(isinstance(value, DeviceCredential) for value in session.added)
    assert session.commit_calls == 1


@pytest.mark.asyncio
async def test_expired_campaign_is_rejected_without_secret_reflection() -> None:
    """Invalid or expired authority must fail closed without persisting or reflecting secrets."""
    campaign = _campaign()
    campaign.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    session, token = await _authorized_session(
        scopes=(PROVISIONING_SCOPE,), campaign=campaign
    )
    app = create_app(_settings(), session_provider=_Provider(session))
    secret_marker = "expired-install-session-secret-marker"
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/v1/provisioning/install-claims",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "campaign_id": str(campaign.id),
                "install_session_id": secret_marker,
                "hardware_fingerprint": "sha256:alt-hardware-001",
            },
        )

    assert response.status_code == 404
    assert secret_marker not in response.text
    assert session.added == []
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


@pytest.mark.asyncio
async def test_provisioning_claim_input_is_bounded_and_redacted() -> None:
    """An oversized session binding cannot be stored or reflected by validation errors."""
    campaign = _campaign()
    session, token = await _authorized_session(
        scopes=(PROVISIONING_SCOPE,), campaign=campaign
    )
    app = create_app(_settings(), session_provider=_Provider(session))
    marker = "oversized-secret-session-marker"
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/v1/provisioning/install-claims",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "campaign_id": str(campaign.id),
                "install_session_id": marker + ("x" * 256),
                "hardware_fingerprint": "sha256:alt-hardware-001",
            },
        )

    assert response.status_code == 422
    assert marker not in response.text
    assert session.added == []


@pytest.mark.asyncio
async def test_provisioning_claim_rejects_noncanonical_hardware_fingerprint() -> None:
    """A printable label is not a hardware proof and must not become a claim binding."""
    campaign = _campaign()
    session, token = await _authorized_session(
        scopes=(PROVISIONING_SCOPE,), campaign=campaign
    )
    app = create_app(_settings(), session_provider=_Provider(session))
    marker = "sha256:arbitrary printable fingerprint"
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            "/api/v1/provisioning/install-claims",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "campaign_id": str(campaign.id),
                "install_session_id": "alt-session-canonical",
                "hardware_fingerprint": marker,
            },
        )

    assert response.status_code == 422
    assert marker not in response.text
    assert session.added == []
    assert session.commit_calls == 0


@pytest.mark.asyncio
async def test_provisioning_claim_rolls_back_when_required_audit_fails() -> None:
    """A raw claim must never be released if its issuance audit cannot commit."""
    campaign = _campaign()
    session, token = await _authorized_session(
        scopes=(PROVISIONING_SCOPE,), campaign=campaign
    )
    session.fail_audit = True
    app = create_app(_settings(), session_provider=_Provider(session))

    with pytest.raises(RuntimeError, match="injected audit failure"):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://endpoint.sosnadmin.local",
        ) as client:
            await client.post(
                "/api/v1/provisioning/install-claims",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "campaign_id": str(campaign.id),
                    "install_session_id": "alt-session-transaction",
                    "hardware_fingerprint": "sha256:alt-hardware-transaction",
                },
            )

    assert session.commit_calls == 0
    assert session.rollback_calls == 1
