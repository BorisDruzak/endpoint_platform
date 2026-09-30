"""Exercise real device/service authentication through the possession API."""
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import JSON, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.service_tokens import create_service_credential
from endpoint_server.config import Settings
from endpoint_server.db.models import Device, DeviceCredential, ServiceClient, ServiceCredential, AuditEvent
from endpoint_server.enrollment.credentials import device_token_digest
from endpoint_server.main import create_app
from endpoint_server.context.models import ContextCurrent, ContextSnapshot, ContextCollection


def test_binding_openapi_declares_its_actual_constant_error_shape():
    from tools.contracts.generate_contract_artifacts import _service_operation_openapi
    paths = _service_operation_openapi()["paths"]
    for path in ("/api/v1/device-binding/challenges", "/api/v1/device-binding/challenges/redeem"):
        operation = paths[path]["post"]
        assert operation["responses"]["422"]["content"]["application/json"]["schema"] == {
            "$ref":"#/components/schemas/DeviceBindingErrorV1"}
        assert len(operation["security"]) == 1


@pytest.fixture
async def api():
    from endpoint_server.db.models import DeviceBindingChallenge, DeviceBindingThrottle
    # Service scopes use native PostgreSQL ARRAY. Only this SQLite fixture
    # substitutes JSON; production PostgreSQL acceptance remains separate.
    scope_column = ServiceCredential.__table__.c.scopes
    original_scope_type = scope_column.type
    scope_column.type = JSON()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(lambda sync: Device.metadata.create_all(sync, tables=[
            Device.__table__, DeviceCredential.__table__, ServiceClient.__table__,
            ServiceCredential.__table__, AuditEvent.__table__,
            ContextCollection.__table__, ContextSnapshot.__table__, ContextCurrent.__table__,
            DeviceBindingChallenge.__table__, DeviceBindingThrottle.__table__]))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    device_id = uuid4()
    async with sessions() as session:
        session.add(Device(id=device_id, device_identifier="fixture", display_name="PC"))
        session.add(ServiceClient(id=(client_id := uuid4()), client_identifier="helpdesk", display_name="Helpdesk"))
        await session.flush()
        session.add(DeviceCredential(device_id=device_id, credential_identifier="fixture",
            token_digest=device_token_digest("test-device-token", b"device-pepper")))
        issued = await create_service_credential(session, client_id, b"service-pepper",
            actor_kind="admin", actor_identifier="fixture", request_id="fixture",
            scopes=["device-binding.redeem"])
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local", device_token_pepper=b"device-pepper",
        service_token_pepper=b"service-pepper", session_secret=b"session-secret",
        allowed_agent_cidrs=(ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ip_network("127.0.0.0/8"),), artifact_root=Path("artifacts"))
    app = create_app(settings, sessions)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://endpoint.sosnadmin.local") as client:
        yield client, sessions, device_id, issued.token
    await engine.dispose()
    scope_column.type = original_scope_type


@pytest.mark.asyncio
async def test_device_auth_and_bounded_redeem_projection(api):
    client, sessions, device_id, service_token = api
    path = "/api/v1/device-binding/challenges"
    assert (await client.post(path, json={"purpose":"helpdesk_device_binding"})).status_code == 401
    headers = {"Authorization":"Bearer test-device-token"}
    malicious = await client.post(path, headers=headers, json={"purpose":"helpdesk_device_binding", "device_id":str(uuid4())})
    assert malicious.status_code == 422
    created = await client.post(path, headers=headers, json={"purpose":"helpdesk_device_binding"})
    assert created.status_code == 200
    assert created.headers["cache-control"] == "no-store"
    code = created.json()["code"]
    body = {"purpose":"helpdesk_device_binding", "code":code}
    assert (await client.post(path+"/redeem", headers=headers, json=body)).status_code == 401
    redeemed = await client.post(path+"/redeem", headers={"Authorization":f"Bearer {service_token}"}, json=body)
    assert redeemed.status_code == 200
    assert redeemed.json()["device_id"] == str(device_id)
    assert set(redeemed.json()) == {"status", "device_id", "hostname", "platform"}
    replay = await client.post(path+"/redeem", headers={"Authorization":f"Bearer {service_token}"}, json=body)
    invalid = await client.post(path+"/redeem", headers={"Authorization":f"Bearer {service_token}"}, json={**body,"code":"000000" if code!="000000" else "999999"})
    assert replay.status_code == invalid.status_code == 400
    assert replay.json() == invalid.json()
    async with sessions() as session:
        events = (await session.scalars(select(AuditEvent))).all()
        assert any(e.action == "device_binding.challenge_created" for e in events)
        assert any(e.action == "device_binding.challenge_redeemed" for e in events)
        assert all(code not in str(e.details) for e in events)


@pytest.mark.asyncio
async def test_failed_attempts_are_durable_and_throttled(api, monkeypatch):
    from endpoint_server.device_binding import routes
    from endpoint_server.device_binding.service import consume_budget
    from endpoint_server.db.models import DeviceBindingThrottle
    client, sessions, device_id, service_token = api
    headers = {"Authorization":f"Bearer {service_token}"}
    started_at = datetime.now(UTC)
    clock = [started_at]
    async def timed_budget(session, bucket, **kwargs):
        await consume_budget(session, bucket, now=clock[0], **kwargs)
    monkeypatch.setattr(routes, "consume_budget", timed_budget)
    for index in range(60):
        # Stay below the unchanged 30/min request budgets while attacking the
        # same ServiceClient from distributed requester identities upstream.
        clock[0] = started_at + timedelta(seconds=index * 3)
        response = await client.post("/api/v1/device-binding/challenges/redeem", headers=headers,
            json={"purpose":"helpdesk_device_binding", "code":"999999"})
        assert response.status_code == 400
    async with sessions() as session:
        bucket = await session.scalar(select(DeviceBindingThrottle).where(DeviceBindingThrottle.bucket.like("failed:%")))
        assert bucket.attempts == 60
    blocked = await client.post("/api/v1/device-binding/challenges/redeem", headers=headers,
        json={"purpose":"helpdesk_device_binding", "code":"999999"})
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "600"
    assert blocked.headers["cache-control"] == "no-store"
    clock[0] = started_at + timedelta(seconds=600)
    assert (await client.post("/api/v1/device-binding/challenges/redeem", headers=headers,
        json={"purpose":"helpdesk_device_binding", "code":"999999"})).status_code == 400


@pytest.mark.asyncio
async def test_five_bad_codes_leave_valid_code_available_for_same_service_client(api):
    from endpoint_server.db.models import DeviceBindingThrottle
    client, sessions, device_id, service_token = api
    path = "/api/v1/device-binding/challenges"
    created = await client.post(path, headers={"Authorization":"Bearer test-device-token"},
        json={"purpose":"helpdesk_device_binding"})
    assert created.status_code == 200
    code = created.json()["code"]
    bad_code = "000000" if code != "000000" else "999999"
    headers = {"Authorization":f"Bearer {service_token}"}
    for _ in range(5):
        invalid = await client.post(path+"/redeem", headers=headers,
            json={"purpose":"helpdesk_device_binding", "code":bad_code})
        assert invalid.status_code == 400
    valid = await client.post(path+"/redeem", headers=headers,
        json={"purpose":"helpdesk_device_binding", "code":code})
    assert valid.status_code == 200
    assert valid.json()["device_id"] == str(device_id)
    async with sessions() as session:
        bucket = await session.scalar(select(DeviceBindingThrottle).where(DeviceBindingThrottle.bucket.like("failed:%")))
        assert bucket.attempts == 5  # success adds no shared failure
    replay = await client.post(path+"/redeem", headers=headers,
        json={"purpose":"helpdesk_device_binding", "code":code})
    assert replay.status_code == invalid.status_code == 400
    assert replay.json() == invalid.json()


@pytest.mark.asyncio
async def test_missing_dedicated_service_scope_is_forbidden(api):
    client, sessions, device_id, service_token = api
    async with sessions() as session:
        credential = await session.scalar(select(ServiceCredential))
        credential.scopes = ["devices.read"]
        await session.commit()
    response = await client.post("/api/v1/device-binding/challenges/redeem",
        headers={"Authorization":f"Bearer {service_token}"},
        json={"purpose":"helpdesk_device_binding", "code":"123456"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_successful_bindings_do_not_exhaust_failed_attempt_budget(api):
    from endpoint_server.device_binding.service import create_challenge
    client, sessions, device_id, service_token = api
    for _ in range(6):
        async with sessions() as session:
            device = Device(id=uuid4(), device_identifier=uuid4().hex)
            session.add(device)
            await session.commit()
            proof = await create_challenge(session, device.id, b"device-pepper")
            await session.commit()
        response = await client.post("/api/v1/device-binding/challenges/redeem",
            headers={"Authorization":f"Bearer {service_token}"},
            json={"purpose":"helpdesk_device_binding", "code":proof.code})
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_binding_validation_never_reflects_attacker_field_names_or_values(api):
    client, sessions, device_id, service_token = api
    response = await client.post("/api/v1/device-binding/challenges/redeem",
        headers={"Authorization":f"Bearer {service_token}"},
        json={"purpose":"helpdesk_device_binding","code":"123456","sensitive-fixture-code": "credential-fixture"})
    assert response.status_code == 422
    assert response.json() == {"detail":"Invalid binding request"}


@pytest.mark.asyncio
async def test_device_revoked_during_lock_wait_cannot_create_proof(api, monkeypatch):
    from sqlalchemy import update
    from endpoint_server.device_binding import routes
    client, sessions, device_id, service_token = api
    consume = routes.consume_budget
    async def revoke_after_initial_auth(session, bucket, **kwargs):
        await consume(session, bucket, **kwargs)
        if bucket.startswith("create:"):
            async with sessions() as other:
                await other.execute(update(DeviceCredential).values(revoked_at=datetime.now(UTC)))
                await other.commit()
    monkeypatch.setattr(routes, "consume_budget", revoke_after_initial_auth)
    response = await client.post("/api/v1/device-binding/challenges",
        headers={"Authorization":"Bearer test-device-token"},
        json={"purpose":"helpdesk_device_binding"})
    assert response.status_code == 401
