"""Exact release inclusion in a separately approved ALT native campaign."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_server.db.models import AuditEvent
from endpoint_server.db.session import create_session_provider
from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
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
