"""Read first-install acceptance evidence from the selected Lab provider."""

from argparse import Namespace
import asyncio
from datetime import UTC, datetime, timedelta
import os

from pydantic import ValidationError
from sqlalchemy import select, text

from endpoint_contracts.context import DeviceContextEnvelopeV1
from endpoint_contracts.installation_lifecycle import InstallationEventAckV1
from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationEventV1
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.projection import activity_current_projection
from endpoint_server.db.models import (
    Command, CommandDelivery, CommandResult, Device, DeviceCredential, DeviceInstance,
    DeviceSession, EnrollmentCampaign, EnrollmentClaim, EnrollmentRequest,
)
from endpoint_server.db.session import create_session_provider
from endpoint_server.enrollment.linux_models import LinuxEnrollmentBinding
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
from endpoint_server.installation_lifecycle.models import InstallationEvent, InstallationState
from tools.release import agent_alt_native
from tools.release.agent_candidate_artifacts import alt_rpm_names


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _source(candidate):
    members = candidate["members"]
    core, sensor = alt_rpm_names(members, candidate["version"])
    return {"version": candidate["version"], "source_revision": candidate["build_revision"],
            "core_nevra": core.removesuffix(".rpm"), "core_rpm_sha256": members[core]["sha256"],
            "user_sensor_nevra": sensor.removesuffix(".rpm"), "user_sensor_rpm_sha256": members[sensor]["sha256"]}


async def _registered_request(session, request_id, device_id, now):
    result = await session.execute(
        select(EnrollmentRequest, EnrollmentClaim, DeviceCredential, LinuxNativeRelease)
        .join(Device, Device.id == EnrollmentRequest.device_id)
        .join(LinuxEnrollmentBinding, LinuxEnrollmentBinding.enrollment_request_id == EnrollmentRequest.id)
        .join(LinuxNativeRelease, LinuxNativeRelease.id == LinuxEnrollmentBinding.native_release_id)
        .join(EnrollmentClaim, EnrollmentClaim.id == LinuxEnrollmentBinding.claim_id)
        .join(EnrollmentCampaign, EnrollmentCampaign.id == EnrollmentClaim.campaign_id)
        .join(DeviceCredential, DeviceCredential.id == LinuxEnrollmentBinding.credential_id)
        .where(EnrollmentRequest.id == request_id, Device.id == device_id, Device.retired_at.is_(None),
               EnrollmentRequest.platform == "linux",
               EnrollmentRequest.status.in_(("device_registered", "waiting_wss", "completed")),
               EnrollmentRequest.selected_campaign_id == EnrollmentClaim.campaign_id,
               EnrollmentClaim.enrollment_request_id == request_id, EnrollmentClaim.device_id == device_id,
               EnrollmentClaim.claimed_at.is_not(None), EnrollmentClaim.claimed_at <= now,
               EnrollmentClaim.fingerprint_digest == LinuxEnrollmentBinding.claim_fingerprint_digest,
               EnrollmentCampaign.target_platform == "linux", DeviceCredential.device_id == device_id,
               DeviceCredential.revoked_at.is_(None),
               DeviceCredential.expires_at.is_(None) | (DeviceCredential.expires_at > now),
               LinuxNativeRelease.retired_at.is_(None))
    )
    return result.one_or_none()


async def _first_installation(session, device_id, credential_id):
    return await session.scalar(
        select(InstallationEvent)
        .join(InstallationState, InstallationState.event_id == InstallationEvent.id)
        .where(InstallationState.device_id == device_id, InstallationState.state == "installed",
               InstallationState.sequence == 1, InstallationEvent.device_id == device_id,
               InstallationEvent.source_credential_id == credential_id,
               InstallationEvent.action == "installed", InstallationEvent.sequence == 1,
               InstallationState.generation_id == InstallationEvent.generation_id)
    )


def _accepted_ack(event, source, claim_time, now):
    try:
        body = LinuxInstallationEventV1.model_validate(event.payload)
        ack = InstallationEventAckV1.model_validate(event.acknowledgement)
    except ValidationError:
        return False
    return (body.device_id == ack.device_id == event.device_id
            and body.event_id == ack.event_id == event.id
            and body.generation_id == ack.generation_id == event.generation_id
            and body.sequence == ack.sequence == 1 and body.action == ack.state == "installed"
            and body.native.model_dump(exclude={"exit_code"}) == source
            and body.previous_event_id is None
            and _utc(claim_time) <= ack.received_at == _utc(event.received_at) <= now)


async def _fresh_connection(session, device_id, version, installed_at, now):
    cutoff = now - timedelta(seconds=90)
    rows = (await session.execute(
        select(DeviceSession, DeviceInstance)
        .join(DeviceInstance, DeviceInstance.id == DeviceSession.device_instance_id)
        .where(DeviceSession.device_id == device_id, DeviceSession.closed_at.is_(None),
               DeviceSession.expires_at > now, DeviceSession.last_seen_at.between(cutoff, now))
        .limit(2)
    )).all()
    if len(rows) != 1:
        return None
    connection, instance = rows[0]
    if (instance.device_id != device_id or instance.platform != "linux_amd64" or instance.agent_version != version
            or instance.last_seen_at is None or not cutoff <= _utc(instance.last_seen_at) <= now
            or not installed_at <= _utc(connection.created_at) <= _utc(connection.last_seen_at)):
        return None
    return connection


async def _baseline(session, device_id, connection, now):
    # The result row's creation time is server-owned. Collection completion
    # and snapshot timestamps can both come from the device clock.
    session_started = _utc(connection.created_at)
    clock_slack = timedelta(seconds=30)
    snapshot = await session.scalar(
        select(ContextSnapshot)
        .join(ContextCurrent, ContextCurrent.snapshot_id == ContextSnapshot.id)
        .join(ContextCollection, ContextCollection.id == ContextSnapshot.collection_id)
        .join(CommandResult, CommandResult.id == ContextCollection.command_result_id)
        .join(CommandDelivery, CommandDelivery.id == CommandResult.delivery_id)
        .join(Command, Command.id == CommandResult.command_id)
        .where(ContextCurrent.device_id == device_id, ContextCurrent.profile == "baseline_v1",
               ContextSnapshot.device_id == device_id, ContextSnapshot.profile == "baseline_v1",
               ContextCollection.device_id == device_id, ContextCollection.profile == "baseline_v1",
               ContextCollection.status == "completed", ContextCollection.command_id == Command.id,
               Command.device_id == device_id, Command.command_kind == "context.baseline.collect",
               CommandResult.status == "succeeded", CommandDelivery.command_id == Command.id,
               CommandDelivery.device_session_id == connection.id,
               CommandResult.created_at.between(session_started, now),
               ContextSnapshot.collected_at.between(session_started - clock_slack, now + clock_slack))
    )
    if snapshot is None:
        return None
    try:
        envelope = DeviceContextEnvelopeV1.model_validate(snapshot.normalized_projection)
    except ValidationError:
        return None
    if envelope.profile != "baseline_v1":
        return None
    system = envelope.sections.system
    if system.platform != "linux" or system.architecture != "x86_64" or not system.distribution.casefold().startswith("alt "):
        return None
    return snapshot


async def _interactive_activity(session, device_id, connection, now):
    current = await session.scalar(
        select(ContextCurrent).where(ContextCurrent.device_id == device_id, ContextCurrent.profile == "activity_v1")
    )
    activity = activity_current_projection(current) if current is not None else None
    if activity is None:
        return None
    sections = activity["sections"]
    collected, observed = activity["collected_at"], _utc(activity["last_observed_at"])
    cutoff = max(_utc(connection.created_at), now - timedelta(seconds=150))
    if (sections["session_state"] not in {"ACTIVE", "IDLE"} or not sections["user_login"]
            or not cutoff <= collected <= observed <= now):
        return None
    return collected


async def evaluate_first_enrollment(session, candidate, request_id, device_id, *, now):
    """Evaluate the exact first-install route. Return no private context fields."""
    source = _source(candidate)
    result = {"enrollment_request_id": str(request_id), "device_id": str(device_id)}
    registered = await _registered_request(session, request_id, device_id, now)
    if registered is None:
        return {**result, "state": "hold", "reason": "exact_registered_request_required"}
    request, claim, credential, release = registered
    result.update(enrollment_status=request.status, native_release_id=str(release.id))
    if (request.installer_release_id != str(release.id) or request.installer_version != source["version"]
            or any(getattr(release, name) != value for name, value in source.items())
            or release.signer_fingerprint != candidate["publisher_fingerprint"]
            or release.frozen_manifest_sha256 != candidate["frozen_manifest_sha256"]):
        return {**result, "state": "hold", "reason": "native_release_mismatch"}
    event = await _first_installation(session, device_id, credential.id)
    if event is None or not _accepted_ack(event, source, claim.claimed_at, now):
        return {**result, "state": "hold", "reason": "native_installation_missing"}
    result.update(native_event_id=str(event.id), native_sequence=event.sequence)
    connection = await _fresh_connection(session, device_id, source["version"], _utc(event.received_at), now)
    if connection is None:
        return {**result, "state": "hold", "reason": "fresh_matching_wss_required"}
    result["session_id"] = str(connection.id)
    baseline = await _baseline(session, device_id, connection, now)
    if baseline is None:
        return {**result, "state": "hold", "reason": "post_install_baseline_required"}
    result["baseline_snapshot_id"] = str(baseline.id)
    activity_at = await _interactive_activity(session, device_id, connection, now)
    if activity_at is None:
        return {**result, "state": "hold", "reason": "interactive_activity_required"}
    return {**result, "state": "accepted", "activity_collected_at": activity_at.isoformat()}


async def _inspect_provider(database_url, args, candidate):
    provider = create_session_provider(database_url)
    try:
        async with provider() as session:
            if session.get_bind().dialect.name == "postgresql":
                await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
            now = datetime.now(UTC)
            result = await evaluate_first_enrollment(
                session, candidate, args.enrollment_request_id, args.device_id, now=now)
        return {**result, "checked_at": now.isoformat()}
    finally:
        await provider.close()


def qualify(args: Namespace) -> dict:
    candidate = agent_alt_native.recorded_kit(args)
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL is required for the selected Lab provider")
    with agent_alt_native.verified_kit(candidate, args):
        result = asyncio.run(_inspect_provider(database_url, args, candidate))
    return {**result, "schema_version": 1, "platform": "alt", "scope": "first_enrollment",
            "request_id": candidate["request_id"], "version": candidate["version"],
            "build_revision": candidate["build_revision"], "kit_sha256": candidate["artifacts"]["archive"]["sha256"]}
