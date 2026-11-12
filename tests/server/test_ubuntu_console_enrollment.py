from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

from endpoint_server.enrollment import ubuntu_requests
from endpoint_server.enrollment.campaigns import EnrollmentDenied
from endpoint_server.enrollment.linux_requests import linux_campaign_allows
from tests.server.test_update_postgresql import update_migration_database_urls


def payload():
    return {
        "schema_version": "ubuntu_deb_enrollment_request_v1",
        "installation_id": "ubuntu-fixture",
        "hardware_fingerprint": "sha256:" + "0" * 64,
        "request_capability": "A" * 43,
        "hostname": "openvpn",
        "package_version": "3.2.192-1ubuntu1",
        "package_sha256": "8affee69264c5cbdc76237ba83dfe5db91ab7a34562ee92f024d9d2b24471a7d",
    }


@pytest.mark.parametrize("address, hostname", [
    ("192.168.100.30", "openvpn"),
    ("192.168.100.27", "dirpost"),
])
def test_exact_deb_becomes_manual_and_can_only_use_its_host_campaign(address, hostname):
    now = datetime.now(UTC)
    record, _ = ubuntu_requests.build_request(
        ubuntu_requests.UbuntuDebRequest.model_validate(payload() | {"hostname": hostname}),
        address=ip_address(address), pepper=b"test", now=now,
    )
    assert record.status == "waiting_approval"
    assert record.selected_campaign_id is None
    assert record.expires_at <= now + timedelta(minutes=20)
    campaign = ubuntu_requests.build_campaign(record, pepper=b"test", now=now)
    record.selected_campaign_id = campaign.id
    assert campaign.allowed_cidrs == [f"{address}/32"]
    assert campaign.max_uses == 1
    assert linux_campaign_allows(record, campaign, now=now)
    campaign.allowed_cidrs = ["192.168.100.0/24"]
    assert not linux_campaign_allows(record, campaign, now=now)


@pytest.mark.parametrize("address, changes", [
    ("192.168.100.31", {}),
    ("192.168.100.19", {}),
    ("192.168.100.27", {}),
    ("192.168.100.31", {"hostname": "dirpost"}),
    ("192.168.100.30", {"package_sha256": "f" * 64}),
])
def test_rejects_other_hosts_and_unreviewed_deb(address, changes):
    with pytest.raises(EnrollmentDenied):
        ubuntu_requests.build_request(
            ubuntu_requests.UbuntuDebRequest.model_validate(payload() | changes),
            address=ip_address(address), pepper=b"test", now=datetime.now(UTC),
        )


def test_debian_deb_keeps_its_release_and_single_host_approval():
    now = datetime.now(UTC)
    body = ubuntu_requests.DebianDebRequest.model_validate(payload() | {
        "schema_version": "debian_deb_enrollment_request_v1",
        "hostname": "pve1",
        "package_version": "3.2.193-1deb12u1",
        "package_sha256": "cc8ebf1da12d9f8106dd1ab627cd1517a3801c63c1315cf19524c54370b967fc",
    })
    record, _ = ubuntu_requests.build_request(
        body, address=ip_address("10.83.1.11"), pepper=b"test", now=now,
    )
    assert record.installer_release_id == "debian-deb:3.2.193-1deb12u1"
    assert record.status == "waiting_approval"
    campaign = ubuntu_requests.build_campaign(record, pepper=b"test", now=now)
    record.selected_campaign_id = campaign.id
    assert campaign.allowed_cidrs == ["10.83.1.11/32"]
    assert campaign.max_uses == 1
    assert linux_campaign_allows(record, campaign, now=now)
    for wrong_body, address in [
        (body, "10.83.1.12"),
        (body, "10.83.1.14"),
        (body.model_copy(update={"package_sha256": "f" * 64}), "10.83.1.11"),
    ]:
        with pytest.raises(EnrollmentDenied):
            ubuntu_requests.build_request(wrong_body, address=ip_address(address), pepper=b"test", now=now)
    campaign.policy = {**campaign.policy, "allowed_native_releases": [str(ubuntu_requests.POLICY_RELEASE)]}
    assert not linux_campaign_allows(record, campaign, now=now)


async def run_ubuntu_enrollment_scenario(database_url: str):
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import select
    from endpoint_server.auth.passwords import hash_password
    from endpoint_server.config import Settings
    from endpoint_server.db.models import AdminUser, EnrollmentCampaign, EnrollmentClaim, EnrollmentRequest
    from endpoint_server.db.session import AsyncSessionProvider
    from endpoint_server.main import create_app

    provider = AsyncSessionProvider(database_url)
    settings = Settings(
        database_url=database_url, public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"ubuntu-test-device", service_token_pepper=b"ubuntu-test-service",
        session_secret=b"ubuntu-test-session", allowed_admin_cidrs=(),
        allowed_agent_cidrs=(ip_network("192.168.100.0/24"), ip_network("127.0.0.0/8")),
        artifact_root=Path("artifacts"),
    )
    app = create_app(settings, session_provider=provider)
    origin = settings.public_base_url
    body = payload()
    proof = {key: body[key] for key in ("request_capability", "installation_id", "hardware_fingerprint")}
    try:
        async with provider() as session:
            session.add(AdminUser(username="ubuntu-fixture", password_digest=hash_password("isolated-fixture-password"),
                                  disabled_at=None, scopes=[]))
            await session.commit()
        async with (
            AsyncClient(transport=ASGITransport(app=app), base_url=origin) as console,
            AsyncClient(transport=ASGITransport(app=app, client=("192.168.100.30", 8090)), base_url=origin) as host,
        ):
            intake = "/api/v1/enrollment/ubuntu/requests"
            assert (await console.post(intake, json=body)).status_code == 409
            created = await host.post(intake, json=body)
            assert created.status_code == 201, created.text
            request_id = created.json()["request_id"]
            repeat = await host.post(intake, json=body)
            assert repeat.status_code == 200 and repeat.json() == created.json()
            assert (await host.post(intake, json=body | {"installation_id": "other-attempt"})).status_code == 409
            approval = f"/api/admin/enrollment/requests/{request_id}/approve"
            claim_path = f"/api/v1/enrollment/linux/requests/{request_id}/claim"
            assert (await host.post(claim_path, json=proof)).status_code == 409
            assert (await console.post(approval)).status_code == 401
            login = await console.post("/api/admin/session", json={
                "username": "ubuntu-fixture", "password": "isolated-fixture-password",
            })
            assert login.status_code == 201, login.text
            csrf = {"X-CSRF-Token": login.json()["csrf_token"]}
            detail = await console.get(f"/api/admin/console/enrollment/requests/{request_id}")
            assert detail.status_code == 200 and detail.json()["data"]["installer_kind"] == "deb"
            assert detail.json()["data"]["selected_campaign_id"] is None
            assert (await console.post(approval)).status_code == 403
            approved = await console.post(approval, headers=csrf)
            assert approved.status_code == 204, approved.text
            assert (await console.post(approval, headers=csrf)).status_code == 409
            assert (await host.post(claim_path, json=proof | {"request_capability": "B" * 43})).status_code == 404
            handed = await host.post(claim_path, json=proof)
            assert handed.status_code == 200, handed.text
            retry = await host.post(claim_path, json=proof)
            assert retry.json() == handed.json()
            headers = {"Authorization": "Bearer " + handed.json()["claim"]}
            enroll = {
                "schema_version": "agent_enrollment_request_v1", "platform": "linux",
                "installation_id": body["installation_id"], "hardware_fingerprint": body["hardware_fingerprint"],
                "delivery_nonce": "C" * 43, "requested_at": datetime.now(UTC).isoformat(),
            }
            assert (await console.post("/agent/v1/enroll", headers=headers, json=enroll)).status_code == 403
            enrolled = await host.post("/agent/v1/enroll", headers=headers, json=enroll)
            assert enrolled.status_code == 201, enrolled.text
            assert (await host.post("/agent/v1/enroll", headers=headers, json=enroll)).json() == enrolled.json()
        async with provider() as session:
            campaign = await session.scalar(select(EnrollmentCampaign))
            assert campaign.allowed_cidrs == ["192.168.100.30/32"] and campaign.use_count == 1
            record = await session.scalar(select(EnrollmentRequest))
            claim = await session.scalar(select(EnrollmentClaim))
            assert record.status == "device_registered" and record.device_id == claim.device_id
    finally:
        await provider.close()


def test_web_approval_and_capability_handoff_use_one_campaign(update_migration_database_urls):
    import asyncio
    from alembic import command
    from tests.server.test_update_postgresql import _alembic_config

    url, _ = update_migration_database_urls
    command.upgrade(_alembic_config(url), "head")
    asyncio.run(run_ubuntu_enrollment_scenario(url))
