"""Real PostgreSQL assignment, concurrent claim handoff, and receipt flow."""

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
import secrets
from uuid import UUID, uuid4

from alembic import command
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError

from endpoint_contracts import AgentHeartbeatV1, AgentHelloV1
from endpoint_server.auth.scopes import (
    INVENTORY_INSTALLATION_ASSIGNMENTS_ISSUE_SCOPE,
    INVENTORY_INSTALLATION_RECEIPTS_READ_SCOPE,
)
from endpoint_server.auth.service_tokens import create_service_credential
from endpoint_server.db.models import Device, EnrollmentClaim, InventoryInstallationAssignment, ServiceClient
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.enrollment.requests import CampaignSelection, build_enrollment_request
from endpoint_server.gateway.presence_service import PresenceService
from endpoint_server.main import create_app
from tests.gateway.conftest import agent_hello
from tests.server.test_enrollment_request_api import PEPPER, _settings
from tests.server.test_update_postgresql import _alembic_config, update_migration_database_urls


pytestmark = pytest.mark.usefixtures("preserve_migration_loggers")


def test_inventory_assignment_has_one_claim_owner_and_returns_connected_device(update_migration_database_urls):
    url, _ = update_migration_database_urls
    config = _alembic_config(url)
    command.upgrade(config, "head")
    command.downgrade(config, "0051_staging_linux_worktime")
    command.upgrade(config, "head")

    async def scenario():
        provider = AsyncSessionProvider(url)
        settings = replace(_settings(), database_url=url, allowed_agent_cidrs=(ip_network("127.0.0.0/8"),))
        installation_id = f"inventory-{uuid4()}-{uuid4()}-" + secrets.token_hex(16)
        fingerprint = "sha256:fixture-inventory-machine"
        issue_body = {"installation_id": installation_id, "platform": "windows", "hardware_fingerprint": fingerprint}
        lookup_body = {"installation_id": installation_id}
        try:
            async with provider() as session:
                owner = ServiceClient(client_identifier="inventory-fixture", display_name="Inventory Fixture")
                session.add(owner)
                await session.flush()
                credential = await create_service_credential(
                    session, owner.id, settings.service_token_pepper, actor_kind="admin",
                    actor_identifier="fixture", request_id="test-inventory-receipt",
                    scopes=(INVENTORY_INSTALLATION_ASSIGNMENTS_ISSUE_SCOPE, INVENTORY_INSTALLATION_RECEIPTS_READ_SCOPE),
                )
            headers = {"Authorization": f"Bearer {credential.token}"}
            app = create_app(settings, session_provider=provider)
            async with AsyncClient(transport=ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
                assignment_path = "/api/v1/enrollment/installation-assignments"
                receipt_path = "/api/v1/enrollment/installation-receipts/lookup"
                issued = await client.post(assignment_path, json=issue_body, headers=headers)
                assert issued.status_code == 200
                async with provider() as session:
                    assignment = await session.scalar(select(InventoryInstallationAssignment))
                    assignment.expires_at = datetime.now(UTC) + timedelta(minutes=2)
                    expires = assignment.expires_at
                    requests = []
                    capabilities = [secrets.token_urlsafe(32), secrets.token_urlsafe(32)]
                    campaigns = []
                    for capability in capabilities:
                        campaign = issue_campaign(
                            PEPPER, expires_at=datetime.now(UTC) + timedelta(hours=1), max_uses=2,
                            allowed_cidrs=("127.0.0.0/8",), target_platform="windows", policy={
                                "policy_id": "fixture-inventory", "enrollment_mode": "manual",
                                "allowed_installer_releases": ["1.0.0"],
                            },
                        )
                        campaigns.append(campaign)
                        session.add(campaign.record)
                        record = build_enrollment_request(
                            installation_id=installation_id, hardware_fingerprint=fingerprint,
                            request_capability=capability, source_address=ip_address("127.0.0.1"),
                            installer_version="1.0.0", installer_release_id="1.0.0",
                            hostname="fixture-inventory-pc",
                            selection=CampaignSelection("waiting_approval", campaign.record, "MANUAL_POLICY"),
                            pepper=PEPPER, now=datetime.now(UTC),
                        )
                        record.status = "approved"
                        session.add(record)
                        requests.append(record.id)
                    await session.commit()

                async def get_claim(index):
                    return await client.post(f"/api/v1/enrollment/requests/{requests[index]}/claim", json={
                        "installation_id": installation_id, "hardware_fingerprint": fingerprint,
                        "request_capability": capabilities[index],
                    })

                first, second = await asyncio.gather(get_claim(0), get_claim(1))
                assert sorted((first.status_code, second.status_code)) == [200, 409]
                winner = 0 if first.status_code == 200 else 1
                proof = (first, second)[winner].json()
                assert datetime.fromisoformat(proof["expires_at"]) == expires
                assert (await get_claim(winner)).json() == proof
                enrollment = {
                    "schema_version": "agent_enrollment_request_v1", "platform": "windows",
                    "installation_id": installation_id, "hardware_fingerprint": fingerprint,
                    "delivery_nonce": secrets.token_urlsafe(32), "requested_at": datetime.now(UTC).isoformat(),
                }
                bypass = await client.post("/agent/v1/enroll", json=enrollment,
                                           headers={"Authorization": f"Bearer {campaigns[winner].token}"})
                assert bypass.status_code == 403
                delivery = await client.post("/agent/v1/enroll", json=enrollment,
                                             headers={"Authorization": f"Bearer {proof['claim']}"})
                assert delivery.status_code == 201
                device_id = UUID(delivery.json()["device_id"])
                assert (await client.post(receipt_path, json=lookup_body, headers=headers)).json() == {
                    "state": "waiting_connection",
                }
                presence = PresenceService(provider)
                hello = AgentHelloV1.model_validate({**agent_hello(device_id), "platform": "windows_amd64"})
                connected = await presence.open_session(device_id=device_id, hello=hello, source_address="127.0.0.1")
                assert (await client.post(receipt_path, json=lookup_body, headers=headers)).json() == {
                    "state": "waiting_connection",
                }
                await presence.record_heartbeat(
                    device_id=device_id, session_id=connected.session_id, heartbeat=AgentHeartbeatV1(
                        schema_version="agent_heartbeat_v1", device_id=device_id, platform="windows",
                        agent_version="1.0.0", reported_at=datetime.now(UTC),
                    ),
                )
                receipt = await client.post(receipt_path, json=lookup_body, headers=headers)
                assert receipt.status_code == 200
                assert receipt.json()["state"] == "connected"
                assert receipt.json()["device_id"] == str(device_id)
                assert (await get_claim(1 - winner)).status_code == 409
                async with provider() as session:
                    assert await session.scalar(select(func.count(Device.id))) == 1
                    assert await session.scalar(select(func.count(EnrollmentClaim.id))) == 1
                    assignment = await session.scalar(select(InventoryInstallationAssignment))
                    assert assignment.enrollment_request_id == requests[winner]
        finally:
            await provider.close()

    asyncio.run(scenario())
    with pytest.raises(DBAPIError, match="Inventory installation authority must be preserved"):
        command.downgrade(config, "0051_staging_linux_worktime")
