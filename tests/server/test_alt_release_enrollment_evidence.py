"""Exercise exact first-install evidence against the provider's stored rows."""

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
from endpoint_server.activity.analytics_models import ActivityCursor, ActivityDaily, ActivityInterval
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.db.base import Base
from endpoint_server.db.models import (
    AuditEvent, Command, CommandDelivery, CommandResult, Device, DeviceCredential,
    DeviceInstance, DeviceSession, EnrollmentClaim, EnrollmentRequest,
)
from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.enrollment.linux_models import LinuxEnrollmentBinding
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease, resolve_linux_source
from endpoint_server.installation_lifecycle.models import InstallationEvent, InstallationState
from endpoint_server.installation_lifecycle.service import accept_event
from tests.contracts.test_linux_support_lifecycle import event_data
from tests.server.test_enrollment_postgresql import enrollment_database_url


pytestmark = pytest.mark.usefixtures("preserve_migration_loggers")


@pytest.fixture
def database_url(request):
    if request.param == "postgresql":
        return request.getfixturevalue("enrollment_database_url")
    return None


@pytest.fixture
async def sessions(database_url):
    if database_url:
        engine = create_async_engine(database_url)
        try:
            yield async_sessionmaker(engine, expire_on_commit=False)
        finally:
            await engine.dispose()
        return
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        # The campaign's PostgreSQL ARRAY is outside the read-side projection.
        await connection.execute(text("CREATE TABLE enrollment_campaigns (id CHAR(32), target_platform TEXT)"))
        tables = [model.__table__ for model in (
            ActivityCursor, ActivityDaily, ActivityInterval, AuditEvent, Command, CommandDelivery, CommandResult,
            Device, DeviceCredential,
            DeviceInstance, DeviceSession, EnrollmentClaim, EnrollmentRequest, LinuxEnrollmentBinding,
            LinuxNativeRelease, InstallationEvent, InstallationState, ContextCollection, ContextSnapshot, ContextCurrent,
        )]
        await connection.run_sync(lambda sync: Base.metadata.create_all(sync, tables=tables))
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


@pytest.mark.parametrize("database_url", ["sqlite", "postgresql"], indirect=True)
async def test_alt_qualification_needs_causal_ack_matching_wss_and_interactive_observation(sessions):
    from tools.release.agent_alt_enrollment import evaluate_first_enrollment

    now = datetime.now(UTC)
    registered = now - timedelta(seconds=20)
    installed = now - timedelta(seconds=15)
    connected = now - timedelta(seconds=10)
    observed = now - timedelta(seconds=5)
    baseline_at = connected - timedelta(seconds=2)
    version = "3.2.274"
    core = f"endpoint-agent-{version}-alt6.x86_64"
    sensor = f"endpoint-agent-user-sensor-{version}-alt6.x86_64"
    source = dict(version=version, source_revision="a"*40, core_nevra=core, core_rpm_sha256="b"*64,
                  user_sensor_nevra=sensor, user_sensor_rpm_sha256="c"*64)
    candidate = dict(version=version, build_revision=source["source_revision"], publisher_fingerprint="A"*40,
                     frozen_manifest_sha256="d"*64, members={f"{core}.rpm": {"sha256": "b"*64},
                     f"{sensor}.rpm": {"sha256": "c"*64}, "endpoint-agent-setup": {}, "endpoint-rpm-release.asc": {}})

    async with sessions() as session:
        device = Device(id=uuid4(), device_identifier="alt-qualification")
        credential = DeviceCredential(id=uuid4(), device_id=device.id, token_digest="native-credential",
                                      credential_identifier="initial", created_at=registered)
        release = LinuxNativeRelease(id=uuid4(), **source, signer_fingerprint=candidate["publisher_fingerprint"],
                                      frozen_manifest_sha256=candidate["frozen_manifest_sha256"], reviewed_by="lab")
        if session.get_bind().dialect.name == "postgresql":
            campaign = issue_campaign(
                b"alt-fixture-enrollment-pepper", expires_at=now + timedelta(hours=1),
                max_uses=1, allowed_cidrs=["127.0.0.1/32"], target_platform="linux",
                policy={"policy_id": "test-first", "enrollment_mode": "manual", "allowed_native_releases": [str(release.id)]},
            ).record
            session.add(campaign)
            await session.flush()
            campaign_id = campaign.id
        else:
            campaign_id = uuid4()
            await session.execute(text("INSERT INTO enrollment_campaigns VALUES (:id, 'linux')"), {"id": campaign_id.hex})
        request = EnrollmentRequest(id=uuid4(), device_id=device.id, platform="linux", hostname="alt-qualification",
                                    installer_release_id=str(release.id), installer_version=version,
                                    installation_id_digest="install", fingerprint_digest="request-digest",
                                    request_capability_digest="capability", source_address="127.0.0.1",
                                    selected_campaign_id=campaign_id, status="device_registered",
                                    created_at=registered, expires_at=now + timedelta(hours=1))
        claim = EnrollmentClaim(id=uuid4(), campaign_id=campaign_id, enrollment_request_id=request.id,
                                device_id=device.id, claimed_at=registered, expires_at=request.expires_at,
                                fingerprint_digest="claim-digest", installation_session_digest="install-session",
                                claim_identifier="native-claim", claim_digest="native-claim-digest")
        binding = LinuxEnrollmentBinding(enrollment_request_id=request.id, native_release_id=release.id,
                                         claim_id=claim.id, credential_id=credential.id,
                                         claim_fingerprint_digest=claim.fingerprint_digest)
        session.add_all((device, release))
        await session.flush()
        session.add_all((credential, request))
        await session.flush()
        session.add(claim)
        await session.flush()
        session.add(binding)
        await session.flush()

        async def inspect(target=candidate):
            return await evaluate_first_enrollment(session, target, request.id, device.id, now=now)

        assert (await inspect())["reason"] == "native_installation_missing"
        body = LinuxInstallationEventV1.model_validate(event_data(
            device_id=str(device.id), occurred_at=installed.isoformat(), native={**source, "exit_code": 0}))
        await accept_event(session, SimpleNamespace(device=device, credential=credential), body,
                           request_id="test", source_resolver=resolve_linux_source, now=installed)
        assert (await inspect())["reason"] == "fresh_matching_wss_required"
        instance = DeviceInstance(id=uuid4(), device_id=device.id, instance_identifier="first", platform="linux_amd64",
                                  agent_version=version, last_seen_at=observed)
        connection = DeviceSession(id=uuid4(), device_id=device.id, device_instance_id=instance.id,
                                   session_identifier="native-wss", last_seen_at=observed,
                                   created_at=connected, expires_at=now + timedelta(hours=1))
        command = Command(id=uuid4(), device_id=device.id, command_identifier="baseline", command_kind="context.baseline.collect",
                          status="succeeded")
        delivery = CommandDelivery(id=uuid4(), command_id=command.id, device_session_id=connection.id,
                                   delivery_identifier="baseline-delivery", status="acknowledged")
        result = CommandResult(id=uuid4(), command_id=command.id, delivery_id=delivery.id,
                               result_identifier="baseline-result", created_at=observed, completed_at=baseline_at,
                               status="succeeded")
        collection = ContextCollection(id=uuid4(), device_id=device.id, profile="baseline_v1", requested_by="fixture",
                                       idempotency_key="baseline", status="completed", command_id=command.id,
                                       command_result_id=result.id, requested_at=connected, result_received_at=baseline_at,
                                       completed_at=baseline_at)
        baseline = json.loads(Path("tests/fixtures/context/alt/baseline_v1.json").read_bytes())
        baseline["collected_at"] = baseline_at.isoformat()
        snapshot = ContextSnapshot(id=uuid4(), collection_id=collection.id, device_id=device.id, profile="baseline_v1",
                                   collected_at=baseline_at, normalized_projection=baseline)
        current = ContextCurrent(device_id=device.id, profile="baseline_v1", snapshot_id=snapshot.id, updated_at=observed)
        session.add_all((instance, command))
        await session.flush()
        session.add(connection)
        await session.flush()
        assert (await inspect())["reason"] == "post_install_baseline_required"
        for row in (delivery, result, collection, snapshot, current):
            session.add(row)
            await session.flush()
        assert (await inspect())["reason"] == "interactive_activity_required"

        from endpoint_contracts.activity import ActivityObservationV1
        from endpoint_server.activity.ingestion import ingest_activity_observation

        async def report(login, state, at):
            body = ActivityObservationV1(schema_version="activity_observation_v1", observation_id=uuid4(),
                                         session_state=state, user_login=login,
                                         idle_seconds=10 if state == "ACTIVE" else None, observed_at=at)
            await ingest_activity_observation(session, device.id, body, idle_threshold_seconds=60, received_at=at)

        await report(None, "UNKNOWN", observed)
        assert (await inspect())["reason"] == "interactive_activity_required"
        await report("lab-login", "ACTIVE", observed + timedelta(seconds=1))
        evidence = await inspect()
        assert evidence["state"] == "accepted" and evidence["native_event_id"] == str(body.event_id)
        assert "lab-login" not in json.dumps(evidence)
        assert request.status == "device_registered"
        assert (await inspect({**candidate, "build_revision": "f"*40}))["reason"] == "native_release_mismatch"
        connection.closed_at = now
        await session.flush()
        assert (await inspect())["reason"] == "fresh_matching_wss_required"
