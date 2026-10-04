"""Cancellation acceptance against real migrated, disposable loopback PostgreSQL."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from endpoint_server.auth.admin_sessions import issue_admin_session
from endpoint_server.config import Settings
from endpoint_server.db.models import AdminUser, AuditEvent, Device, UpdateBuild, UpdateReport, UpdateRollout, UpdateTarget
from endpoint_server.main import create_app
from endpoint_server.updates.service import create_rollout, pause_rollout, register_build
from endpoint_server.updates.errors import UpdateStateError
from endpoint_server.updates.admin_contracts import UpdateRolloutCancellationRequestV1
from tests.server.test_update_postgresql import (
    _postgres_manifest,
    update_service_database_url,
    update_service_provider,
)

pytestmark = pytest.mark.usefixtures("preserve_migration_loggers")


@pytest_asyncio.fixture
async def cancellation_case(update_service_provider, update_service_database_url, tmp_path):
    provider = update_service_provider
    secret = b"synthetic-cancellation-session-secret"
    async with provider() as session:
        user = AdminUser(id=uuid4(), username=uuid4().hex, password_digest="synthetic-unused",
            scopes=["updates:write"], disabled_at=None)
        device = Device(id=uuid4(), device_identifier=uuid4().hex, retired_at=None)
        session.add_all([user, device])
        await session.flush()
        issued = issue_admin_session(user.id, secret)
        session.add(issued.record)
        build = await register_build(session, _postgres_manifest(build_identifier=uuid4().hex,
            version=f"2.0.{uuid4().int % 1000000000}", channel="canary", digest_character="a"), user.id, "synthetic-register")
        rollout = await create_rollout(session, build.id, "canary", [device.id], "original context",
            user.id, "synthetic-create")
        await pause_rollout(session, rollout.id, user.id, "synthetic-pause")
        target = await session.scalar(select(UpdateTarget).where(UpdateTarget.rollout_id == rollout.id))
        await session.commit()
        ids = {"user": user.id, "session": issued.record.id, "device": device.id,
            "build": build.id, "rollout": rollout.id, "target": target.id, "operation": target.operation_id}
    settings = Settings(database_url=update_service_database_url,
        public_base_url="https://endpoint.example.test", device_token_pepper=b"synthetic-device",
        service_token_pepper=b"synthetic-service", session_secret=secret,
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),), artifact_root=tmp_path)
    from endpoint_server.updates.admin_transaction import UpdateAdminTransactionProvider
    scoped = UpdateAdminTransactionProvider(update_service_database_url)
    app = create_app(settings, provider, update_admin_provider=scoped)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.example.test", cookies={"endpoint_admin_session": issued.token},
        headers={"x-csrf-token": issued.csrf_token}) as client:
        yield {"provider": provider, "scoped": scoped, "client": client, "app": app,
            "ids": ids, "issued": issued, "secret": secret}
    if scoped is not None:
        await scoped.close()


def path(case, suffix):
    return f"/api/admin/updates/rollouts/{case['ids']['rollout']}/{suffix}"


async def cancellation_body(case):
    response = await case["client"].get(path(case, "cancellation-context"))
    assert response.status_code == 200, response.text
    return {"schema_version": "update_rollout_cancellation_request_v1", "cancellation_id": str(uuid4()),
        "expected": response.json(), "reason": "trial_retired_after_verified_restoration",
        "recovery": {"procedure": "task13_verified_guest_restoration_v1", "run_id": str(uuid4()),
            "evidence_sha256": "b" * 64, "verified_at": datetime.now(UTC).isoformat()}}


@pytest.mark.parametrize("target_status", ["assigned", "requested", "scheduled"])
async def test_cancel_paused_singleton_preserves_history_and_releases_only_owner(cancellation_case, target_status):
    case = cancellation_case
    async with case["provider"]() as session:
        target = await session.get(UpdateTarget, case["ids"]["target"])
        target.status = target_status
        target.safe_reason = "original target context"
        await session.commit()
    body = await cancellation_body(case)
    assert case["ids"]["operation"] not in str(body)
    expected_digest = hashlib.sha256(("endpoint-update-operation-identity-v1\0" +
        str(case["ids"]["operation"])).encode()).hexdigest()
    assert body["expected"]["operation_identity"] == expected_digest
    response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 200, response.text
    replay = await case["client"].post(path(case, "cancel"), json=body)
    assert replay.status_code == 200 and replay.json() == response.json()
    async with case["provider"]() as session:
        target = await session.get(UpdateTarget, case["ids"]["target"])
        rollout = await session.get(UpdateRollout, case["ids"]["rollout"])
        assert (target.status, rollout.status, rollout.completed_at) == ("cancelled", "cancelled", None)
        assert target.safe_reason == "original target context" and rollout.reason == "original context"
        assert target.terminal_at == rollout.cancelled_at == target.updated_at
        assert rollout.paused_at is not None
        assert await session.scalar(select(func.count()).select_from(UpdateTarget).where(
            UpdateTarget.device_id == target.device_id, UpdateTarget.status.in_(("assigned", "requested", "scheduled")))) == 0
        reserved = uuid5(NAMESPACE_URL, "endpoint-platform:update-rollout-cancellation:v1:" + str(rollout.id))
        event = await session.get(AuditEvent, reserved)
        assert event.action == "updates.rollout_cancelled" and event.actor_identifier == str(case["ids"]["user"])
        assert event.details["request"] == UpdateRolloutCancellationRequestV1.model_validate(body).model_dump(mode="json")
        assert event.details["response"] == response.json()
        assert case["ids"]["operation"] not in str(event.details)


@pytest.mark.parametrize("branch,field,value", [
    ("expected", "target_status", "scheduled"), ("expected", "artifact_sha256", "f" * 64),
    ("expected", "operation_identity", "f" * 64), ("expected", "target_id", str(uuid4())),
])
async def test_cancel_requires_exact_paused_canary_context(cancellation_case, branch, field, value):
    case = cancellation_case
    body = await cancellation_body(case)
    body[branch][field] = value
    response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 409
    async with case["provider"]() as session:
        assert (await session.get(UpdateTarget, case["ids"]["target"])).status == "assigned"


@pytest.mark.parametrize("defect", ["extra", "nil", "newline_hash", "naive", "unsafe_reason"])
async def test_cancel_recovery_attestation_is_bounded_and_fresh(cancellation_case, defect):
    case = cancellation_case
    body = await cancellation_body(case)
    if defect == "extra": body["recovery"]["password"] = "sensitive-test-value"
    if defect == "nil": body["cancellation_id"] = "00000000-0000-0000-0000-000000000000"
    if defect == "newline_hash": body["recovery"]["evidence_sha256"] += "\n"
    if defect == "naive": body["recovery"]["verified_at"] = "2026-10-04T00:00:00"
    if defect == "unsafe_reason": body["reason"] = "password=sensitive-test-value"
    response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 422
    assert "sensitive-test-value" not in response.text


@pytest.mark.parametrize("field", ["rollout_id", "rollout_identifier", "paused_at", "build_id",
    "build_identifier", "artifact_name", "target_identifier", "device_id"])
async def test_every_remaining_expected_identity_is_compared(cancellation_case, field):
    case = cancellation_case
    body = await cancellation_body(case)
    body["expected"][field] = (str(uuid4()) if field.endswith("_id") else
        (datetime.now(UTC) + timedelta(seconds=1)).isoformat() if field == "paused_at" else "different-public-identity")
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 409


@pytest.mark.parametrize("defect", ["future", "stale", "pre_pause"])
async def test_first_attestation_time_is_checked_after_waits(cancellation_case, defect):
    case = cancellation_case
    if defect == "stale":
        async with case["provider"]() as session:
            rollout = await session.get(UpdateRollout, case["ids"]["rollout"])
            rollout.paused_at = datetime.now(UTC) - timedelta(hours=1)
            await session.commit()
    body = await cancellation_body(case)
    verified = datetime.now(UTC) + timedelta(seconds=30) if defect == "future" else datetime.now(UTC) - timedelta(minutes=21)
    body["recovery"]["verified_at"] = verified.isoformat()
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 409


@pytest.mark.parametrize("defect", ["zero", "extra", "terminal", "retired", "operation", "identifier",
    "completed_timestamp", "cancelled_timestamp", "terminal_timestamp", "mode", "terminal_report"])
async def test_cancel_full_membership_and_legacy_corruption_fail_closed(cancellation_case, defect):
    case = cancellation_case
    body = await cancellation_body(case)
    async with case["provider"]() as session:
        target = await session.get(UpdateTarget, case["ids"]["target"])
        rollout = await session.get(UpdateRollout, case["ids"]["rollout"])
        if defect == "zero": await session.delete(target)
        if defect == "extra":
            device = Device(id=uuid4(), device_identifier=uuid4().hex, retired_at=None)
            session.add(device)
            await session.flush()
            session.add(UpdateTarget(id=uuid4(), rollout_id=rollout.id, device_id=device.id,
                target_identifier=uuid4().hex, operation_id=str(uuid4()), status="assigned", assigned_at=datetime.now(UTC)))
        if defect == "terminal": target.status = "applied"
        if defect == "retired": (await session.get(Device, target.device_id)).retired_at = datetime.now(UTC)
        if defect == "operation": target.operation_id = "legacy-non-uuid"
        if defect == "identifier": target.target_identifier = "invalid legacy identifier"
        if defect == "completed_timestamp": rollout.completed_at = datetime.now(UTC)
        if defect == "cancelled_timestamp": rollout.cancelled_at = datetime.now(UTC)
        if defect == "terminal_timestamp": target.terminal_at = datetime.now(UTC)
        if defect == "mode": rollout.mode = "bulk"
        if defect == "terminal_report": session.add(UpdateReport(id=uuid4(), update_target_id=target.id,
            device_id=target.device_id, report_identifier=uuid4().hex,
            report_key=uuid4().hex, status="failed", reported_version="2.0.0", safe_code="update.failed"))
        await session.commit()
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 409
    if defect not in ("retired", "terminal_report"):
        assert (await case["client"].get(path(case, "cancellation-context"))).status_code == 409


@pytest.mark.parametrize("defect", ["missing_cookie", "csrf", "scope", "unsorted_scope", "scope_header", "bearer"])
async def test_cancel_requires_persisted_scope_cookie_and_csrf(cancellation_case, defect):
    case = cancellation_case
    body = await cancellation_body(case)
    if defect in ("missing_cookie", "scope_header", "bearer"):
        case["client"].cookies.clear()
        case["client"].headers["x-admin-scopes"] = "updates:write"
        case["client"].headers["authorization"] = "Bearer synthetic-service-bearer"
    if defect == "csrf": case["client"].headers.pop("x-csrf-token")
    if defect in ("scope", "unsorted_scope"):
        async with case["provider"]() as session:
            user = await session.get(AdminUser, case["ids"]["user"])
            user.scopes = [] if defect == "scope" else ["updates:write", "aaa"]
            await session.commit()
    response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == (401 if defect in ("missing_cookie", "scope_header", "bearer") else 403)


@pytest.mark.parametrize("change", ["cancellation_id", "evidence", "run", "actor", "expected"])
async def test_cancel_semantic_replay_is_actor_and_request_bound(cancellation_case, change):
    case = cancellation_case
    body = await cancellation_body(case)
    response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 200
    changed = copy.deepcopy(body)
    if change == "cancellation_id": changed["cancellation_id"] = str(uuid4())
    if change == "evidence": changed["recovery"]["evidence_sha256"] = "c" * 64
    if change == "run": changed["recovery"]["run_id"] = str(uuid4())
    if change == "expected": changed["expected"]["target_status"] = "scheduled"
    if change == "actor":
        async with case["provider"]() as session:
            user = AdminUser(id=uuid4(), username=uuid4().hex, password_digest="synthetic-unused", scopes=["updates:write"])
            session.add(user)
            await session.flush()
            issued = issue_admin_session(user.id, case["secret"])
            session.add(issued.record)
            await session.commit()
        case["client"].cookies.clear()
        case["client"].cookies.set("endpoint_admin_session", issued.token)
        case["client"].headers["x-csrf-token"] = issued.csrf_token
    assert (await case["client"].post(path(case, "cancel"), json=changed)).status_code == 409


async def test_cancel_semantic_replay_accepts_new_session_and_equivalent_utc(cancellation_case):
    case = cancellation_case
    body = await cancellation_body(case)
    first = await case["client"].post(path(case, "cancel"), json=body)
    async with case["provider"]() as session:
        issued = issue_admin_session(case["ids"]["user"], case["secret"])
        session.add(issued.record)
        await session.commit()
    case["client"].cookies.clear()
    case["client"].cookies.set("endpoint_admin_session", issued.token)
    case["client"].headers["x-csrf-token"] = issued.csrf_token
    case["client"].headers["X-Request-ID"] = "different-transport-private-id"
    from datetime import timezone
    body["recovery"]["verified_at"] = datetime.fromisoformat(body["recovery"]["verified_at"]).astimezone(
        timezone(timedelta(hours=5))).isoformat()
    replay = await case["client"].post(path(case, "cancel"), json=body)
    assert replay.status_code == 200 and replay.json() == first.json()


@pytest.mark.parametrize("defect", ["collision", "missing", "state"])
async def test_cancel_audit_collision_or_missing_receipt_fails_closed(cancellation_case, defect):
    case = cancellation_case
    body = await cancellation_body(case)
    reserved = uuid5(NAMESPACE_URL, "endpoint-platform:update-rollout-cancellation:v1:" + str(case["ids"]["rollout"]))
    if defect == "state": assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200
    async with case["provider"]() as session:
        if defect == "collision": session.add(AuditEvent(id=reserved, actor_kind="admin", actor_identifier=str(case["ids"]["user"]),
            action="unrelated", object_kind="update_rollout", object_identifier=str(case["ids"]["rollout"]), request_id="synthetic", details={}))
        else:
            target = await session.get(UpdateTarget, case["ids"]["target"])
            rollout = await session.get(UpdateRollout, case["ids"]["rollout"])
            if defect == "missing":
                target.status = rollout.status = "cancelled"
                rollout.cancelled_at = target.terminal_at = target.updated_at = datetime.now(UTC)
            else: target.updated_at = datetime.now(UTC) + timedelta(seconds=1)
        await session.commit()
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 409


@pytest.mark.parametrize("command", ["UPDATE audit_events SET action='changed' WHERE id=:id", "DELETE FROM audit_events WHERE id=:id"])
async def test_cancel_reserved_audit_receipt_is_append_only(cancellation_case, command):
    case = cancellation_case
    body = await cancellation_body(case)
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200
    reserved = uuid5(NAMESPACE_URL, "endpoint-platform:update-rollout-cancellation:v1:" + str(case["ids"]["rollout"]))
    async with case["provider"]() as session:
        with pytest.raises(DBAPIError): await session.execute(text(command), {"id": reserved})
        await session.rollback()
        assert (await session.get(AuditEvent, reserved)).action == "updates.rollout_cancelled"


async def test_cancel_does_not_qualify_completed_canary_or_resume(cancellation_case):
    case = cancellation_case
    body = await cancellation_body(case)
    assert (await case["client"].post(path(case, "cancel"), json=body)).status_code == 200
    for action in ("activate", "pause", "complete"):
        assert (await case["client"].post(path(case, action))).status_code == 409
    async with case["provider"]() as session:
        with pytest.raises(UpdateStateError):
            await create_rollout(session, case["ids"]["build"], "bulk", [case["ids"]["device"]], None,
                case["ids"]["user"], "synthetic-bulk")


async def test_cancel_model_construct_cannot_bypass_service_validation(cancellation_case, monkeypatch):
    from endpoint_server.updates import admin_routes
    case = cancellation_case
    body = await cancellation_body(case)
    original = admin_routes.cancel_paused_singleton_rollout
    async def forged(session, rollout_id, cancellation, *args, **kwargs):
        invalid = cancellation.model_copy(update={"reason": "password=sensitive-test-value"})
        return await original(session, rollout_id, invalid, *args, **kwargs)
    monkeypatch.setattr(admin_routes, "cancel_paused_singleton_rollout", forged)
    response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 422 and "sensitive-test-value" not in response.text


async def test_cancel_original_attestation_expiry_does_not_prevent_exact_replay(cancellation_case, monkeypatch):
    from endpoint_server.updates import admin_routes
    case = cancellation_case
    body = await cancellation_body(case)
    first = await case["client"].post(path(case, "cancel"), json=body)
    original = admin_routes.cancel_paused_singleton_rollout
    async def later_clock(*args, **kwargs):
        return await original(*args, **kwargs, now=datetime.now(UTC) + timedelta(hours=1))
    monkeypatch.setattr(admin_routes, "cancel_paused_singleton_rollout", later_clock)
    replay = await case["client"].post(path(case, "cancel"), json=body)
    assert replay.status_code == 200 and replay.json() == first.json()


async def test_cancel_append_failure_rolls_back_and_private_header_is_never_receipt(cancellation_case, monkeypatch):
    from endpoint_server.updates import service
    case = cancellation_case
    body = await cancellation_body(case)
    original = service.append_audit_event
    async def fail_append(*args, **kwargs): raise RuntimeError("synthetic append fault")
    with monkeypatch.context() as patch:
        patch.setattr(service, "append_audit_event", fail_append)
        response = await case["client"].post(path(case, "cancel"), json=body)
    assert response.status_code == 503
    async with case["provider"]() as session:
        assert (await session.get(UpdateTarget, case["ids"]["target"])).status == "assigned"
    private_header = "private-transport-session-path-value"
    response = await case["client"].post(path(case, "cancel"), json=body, headers={"X-Request-ID": private_header})
    assert response.status_code == 200 and private_header not in response.text
    reserved = uuid5(NAMESPACE_URL, "endpoint-platform:update-rollout-cancellation:v1:" + str(case["ids"]["rollout"]))
    async with case["provider"]() as session:
        receipt = await session.get(AuditEvent, reserved)
        assert private_header not in str(receipt.details) and private_header != receipt.request_id
        assert case["issued"].token not in str(receipt.details)


async def test_injected_app_requires_explicit_scoped_provider(cancellation_case):
    case = cancellation_case
    from endpoint_server.updates.admin_transaction import NOT_APPLIED
    case["app"].state.update_admin_provider = None
    response = await case["client"].get(path(case, "cancellation-context"))
    assert response.status_code == 503 and response.json()["detail"] == NOT_APPLIED
