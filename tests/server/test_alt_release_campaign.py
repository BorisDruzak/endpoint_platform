"""Exact ALT release inclusion and withdrawal in the owning provider."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationNativeProof
from endpoint_server.db.models import AuditEvent, Device, DeviceCredential, EnrollmentEvent, EnrollmentRetryEnvelope
from endpoint_server.db.session import create_session_provider
from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.enrollment.linux_requests import linux_campaign_allows, select_linux_campaign
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease, resolve_linux_source
from tests.server.test_enrollment_postgresql import enrollment_database_url


pytestmark = pytest.mark.usefixtures("preserve_migration_loggers")


def campaign(now, source, cidrs, *, quota=3):
    return issue_campaign(
        b"alt-fixture-campaign-pepper", expires_at=now + timedelta(hours=1),
        max_uses=quota, allowed_cidrs=cidrs, target_platform="linux",
        policy={"policy_id": "native-first", "enrollment_mode": "manual", "allowed_native_releases": [str(source)]},
        label="Fixture", site="Lab", now=now,
    ).record


def test_alt_campaign_scope_binds_network_mode_and_authority():
    from tools.release.agent_alt_campaign import _campaign_scope

    now = datetime.now(UTC)
    row = campaign(now, uuid4(), ["192.0.2.0/24"])
    first = _campaign_scope(row)
    row.use_count += 1
    assert _campaign_scope(row) == first
    row.allowed_cidrs = ["192.0.2.0/25"]
    assert _campaign_scope(row) != first
    row.allowed_cidrs = first["allowed_cidrs"]
    row.policy = {**row.policy, "enrollment_mode": "auto"}
    assert _campaign_scope(row)["scope_sha256"] != first["scope_sha256"]
    target = uuid4()
    assert _campaign_scope(row, target, "a"*64) != _campaign_scope(row, target, "b"*64)


async def test_alt_release_adds_only_to_reviewed_campaign_and_replays(enrollment_database_url):
    from tools.release.agent_alt_campaign import include_release

    now = datetime.now(UTC)
    source = dict(version="3.2.274", source_revision="a"*40, core_nevra="endpoint-agent-3.2.274-alt6.x86_64",
                  core_rpm_sha256="b"*64, user_sensor_nevra="endpoint-agent-user-sensor-3.2.274-alt6.x86_64",
                  user_sensor_rpm_sha256="c"*64, signer_fingerprint="A"*40, frozen_manifest_sha256="d"*64)
    predecessor = {**source, "version":"3.2.183", "core_nevra":"endpoint-agent-3.2.183-alt6.x86_64",
                   "core_rpm_sha256":"e"*64}
    qualification = {"qualification_id":str(uuid4()), "kit_sha256":"1"*64,
                     "valid_until": (now+timedelta(hours=2)).isoformat()}
    provider = create_session_provider(enrollment_database_url)
    try:
        async with provider() as session:
            active = LinuxNativeRelease(**source, reviewed_by="test")
            prior = LinuxNativeRelease(**predecessor, reviewed_by="test")
            session.add_all((active, prior))
            await session.flush()
            chosen = campaign(now, prior.id, ["192.0.2.7/32"])
            peer = campaign(now, active.id, ["192.0.2.0/24"])
            apt = campaign(now, uuid4(), ["198.51.100.7/32"])
            session.add_all((chosen, peer, apt))
            await session.commit()

            async def stage(target=chosen, **options):
                return await include_release(session, source, qualification, target.id, now=now, **options)

            with pytest.raises(ValueError, match="overlapping"):
                await stage()
            with pytest.raises(ValueError, match="RPM sources"):
                await stage(apt)
            peer.disabled_at = now
            await session.commit()
            preview = await stage()
            assert preview["state"] == "preview" and chosen.policy["allowed_native_releases"] == [str(prior.id)]
            assert preview["native_release_id"] == str(active.id)
            with pytest.raises(ValueError, match="reviewed campaign scope"):
                await stage(execute=True, approved_scope_sha256="0"*64)
            expected = preview["scope_sha256"]
            chosen.use_count = 1
            await session.commit()
            granted = await stage(execute=True, approved_scope_sha256=expected)
            await session.commit()
            assert granted["state"] == "included" and granted["changed"]
            assert chosen.policy["allowed_native_releases"] == [str(prior.id), str(active.id)]
            assert chosen.use_count == 1 and chosen.max_uses == 3 and chosen.allowed_cidrs == ["192.0.2.7/32"]
            assert chosen.expires_at == now+timedelta(hours=1) and chosen.policy["enrollment_mode"] == "manual"
            replay = await stage(execute=True, approved_scope_sha256=expected)
            await session.commit()
            assert replay["state"] == "included" and not replay["changed"]
            logs = (await session.scalars(select(AuditEvent).where(AuditEvent.action=="enrollment_campaign.release_included"))).all()
            assert len(logs)==1 and logs[0].details["qualification_id"]==qualification["qualification_id"]
    finally:
        await provider.close()


async def test_alt_revocation_drains_exact_provider_grants_without_retiring_source(enrollment_database_url):
    from tools.release.agent_alt_campaign import withdraw_release

    now = datetime.now(UTC)
    source = dict(version="3.2.279", source_revision="a" * 40, core_nevra="endpoint-agent-3.2.279-alt6.x86_64",
                  core_rpm_sha256="3" * 64, user_sensor_nevra="endpoint-agent-user-sensor-3.2.279-alt6.x86_64",
                  user_sensor_rpm_sha256="c" * 64, signer_fingerprint="A" * 40, frozen_manifest_sha256="d" * 64)
    predecessor = {**source, "version": "3.2.180", "core_nevra": "endpoint-agent-3.2.180-alt6.x86_64",
                   "core_rpm_sha256": "4" * 64}
    revocation = {"request_id": str(uuid4()), "kit_sha256": "1" * 64, "revoked_at": now.isoformat()}
    provider = create_session_provider(enrollment_database_url)
    try:
        async with provider() as session:
            active = LinuxNativeRelease(**source, reviewed_by="test")
            prior = LinuxNativeRelease(**predecessor, reviewed_by="test")
            session.add_all((active, prior))
            await session.flush()
            mixed = campaign(now, active.id, ["192.0.2.7/32"])
            mixed.policy = {**mixed.policy, "allowed_native_releases": [str(prior.id), str(active.id)]}
            sole = campaign(now, active.id, ["192.0.2.8/32"])
            unrelated = campaign(now, uuid4(), ["198.51.100.7/32"])
            dormant = campaign(now, active.id, ["192.0.2.9/32"])
            dormant.disabled_at = now
            session.add_all((mixed, sole, unrelated, dormant))
            await session.commit()

            async def stage(**options):
                return await withdraw_release(session, source, revocation, now=now, **options)

            def matches(row, selected):
                return select_linux_campaign([row], source_id=selected, now=now, source_address=ip_address("192.0.2.7"))

            issued = SimpleNamespace(platform="linux", installer_release_id=str(active.id),
                                     selected_campaign_id=mixed.id, source_address="192.0.2.7")
            assert linux_campaign_allows(issued, mixed, now=now, consumed=True)
            preview = await stage()
            assert {row["campaign_id"]: row["action"] for row in preview["campaigns"]} == {
                str(mixed.id): "remove_source", str(sole.id): "revoke_campaign", str(dormant.id): "revoke_campaign",
            }
            mixed.allowed_cidrs = ["192.0.2.0/28"]
            await session.commit()
            with pytest.raises(ValueError, match="reviewed withdrawal scope"):
                await stage(execute=True, approved_scope_sha256=preview["scope_sha256"])
            assert linux_campaign_allows(issued, mixed, now=now, consumed=True)
            reviewed = await stage()
            device = Device(device_identifier="alt-withdrawal-pending-delivery")
            session.add(device)
            await session.flush()
            credential = DeviceCredential(device_id=device.id, credential_identifier="fixture", token_digest="fixture-digest")
            session.add(credential)
            await session.flush()
            envelope = EnrollmentRetryEnvelope(device_credential_id=credential.id, receipt_digest="fixture-receipt",
                                               fingerprint_digest="fixture-fingerprint", encrypted_token=b"encrypted",
                                               encryption_nonce=b"nonce", expires_at=now + timedelta(minutes=5))
            session.add_all((envelope, EnrollmentEvent(campaign_id=sole.id, event_kind="device_enrolled",
                                                     remote_identifier=str(device.id))))
            await session.commit()
            hold = await stage()
            assert hold["pending_delivery_campaign_ids"] == [str(sole.id)]
            with pytest.raises(ValueError, match="pending credential delivery"):
                await stage(execute=True, approved_scope_sha256=reviewed["scope_sha256"])
            assert sole.revoked_at is None and await session.get(EnrollmentRetryEnvelope, envelope.id) is envelope
            await session.delete(envelope)
            mixed.use_count = 1
            await session.commit()
            authority = (mixed.allowed_cidrs, mixed.expires_at, mixed.max_uses, mixed.use_count, mixed.token_digest)
            applied = await stage(execute=True, approved_scope_sha256=reviewed["scope_sha256"])
            await session.commit()
            assert applied["state"] == "withdrawn" and applied["changed"]
            assert mixed.policy["allowed_native_releases"] == [str(prior.id)]
            assert authority == (mixed.allowed_cidrs, mixed.expires_at, mixed.max_uses, mixed.use_count, mixed.token_digest)
            assert sole.revoked_at == dormant.revoked_at == now
            assert sole.policy["allowed_native_releases"] == [str(active.id)]
            assert unrelated.revoked_at is None and active.retired_at is None
            assert matches(mixed, prior.id).status == "waiting_approval"
            assert matches(mixed, active.id).status == "review_required"
            assert not linux_campaign_allows(issued, mixed, now=now, consumed=True)
            native_identity = {key: value for key, value in source.items() if key in LinuxInstallationNativeProof.model_fields}
            proof = LinuxInstallationNativeProof.model_validate({"exit_code": 0, **native_identity})
            assert (await resolve_linux_source(session, proof)).id == active.id
            assert credential.revoked_at is None and device.retired_at is None
            replay = await stage(execute=True, approved_scope_sha256=reviewed["scope_sha256"])
            await session.commit()
            assert replay["state"] == "withdrawn" and not replay["changed"]
            logs = (await session.scalars(select(AuditEvent).where(AuditEvent.action == "linux_native_release.enrollment_withdrawn"))).all()
            assert len(logs) == 1 and logs[0].details["scope_sha256"] == reviewed["scope_sha256"]
    finally:
        await provider.close()
