"""Bind a qualified ALT release to one explicitly approved RPM enrollment campaign."""

from argparse import Namespace
import asyncio
from datetime import UTC, datetime
import hashlib
from ipaddress import ip_network
import json
import os

from sqlalchemy import select, text

from endpoint_contracts.linux_enrollment import LinuxEnrollmentPolicyV1
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import EnrollmentCampaign
from endpoint_server.db.session import create_session_provider
from endpoint_server.enrollment.default_campaign import lock_campaign_set
from endpoint_server.enrollment.linux_requests import linux_policy
from endpoint_server.installation_lifecycle.linux_sources import LinuxNativeRelease
from tools.release import agent_alt_qualification
from tools.release.agent_alt_enrollment import _source
from tools.release.agent_candidate_artifacts import SHA256


def _campaign_scope(campaign, release_id=None, kit_sha256=None):
    policy = linux_policy(campaign)
    if policy is None:
        raise ValueError("An existing Linux enrollment policy is required")
    scope = {
        "campaign_id": str(campaign.id),
        "native_release_id": str(release_id) if release_id is not None else None,
        "kit_sha256": kit_sha256,
        "allowed_cidrs": sorted(str(ip_network(cidr, strict=True)) for cidr in campaign.allowed_cidrs),
        "expires_at": campaign.expires_at.astimezone(UTC).isoformat(),
        "max_uses": campaign.max_uses,
        "policy_id": policy.policy_id,
        "enrollment_mode": policy.enrollment_mode,
        "other_native_release_ids": sorted(str(value) for value in policy.allowed_native_releases if value != release_id),
    }
    digest = hashlib.sha256(json.dumps(scope, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**scope, "scope_sha256": digest}


def _active(campaign, now):
    return (campaign.target_platform == "linux" and campaign.disabled_at is None and campaign.revoked_at is None
            and campaign.expires_at is not None and campaign.expires_at > now
            and campaign.use_count < campaign.max_uses)


async def _check_other_campaigns(session, chosen, release_id, now):
    peers = await session.scalars(
        select(EnrollmentCampaign).where(
            EnrollmentCampaign.id != chosen.id, EnrollmentCampaign.target_platform == "linux",
            EnrollmentCampaign.disabled_at.is_(None), EnrollmentCampaign.revoked_at.is_(None),
            EnrollmentCampaign.expires_at > now, EnrollmentCampaign.use_count < EnrollmentCampaign.max_uses,
        )
    )
    local_networks = tuple(ip_network(cidr, strict=True) for cidr in chosen.allowed_cidrs)
    for peer in peers:
        policy = linux_policy(peer)
        if policy is None or release_id not in policy.allowed_native_releases:
            continue
        try:
            remote_networks = tuple(ip_network(cidr, strict=True) for cidr in peer.allowed_cidrs)
        except ValueError:
            # Invalid CIDRs are ineligible in the canonical request selector.
            continue
        if any(left.version == right.version and left.overlaps(right)
               for left in local_networks for right in remote_networks):
            raise ValueError("An overlapping active Linux campaign already allows this exact RPM source")


async def include_release(session, source, qualification, campaign_id, *, execute=False,
                          approved_scope_sha256=None, now=None):
    """Use the same campaign lock order as administrative and enrollment flows."""
    if execute:
        await lock_campaign_set(session)
    campaign = await session.get(EnrollmentCampaign, campaign_id, with_for_update=execute)
    release_query = select(LinuxNativeRelease).where(
        LinuxNativeRelease.retired_at.is_(None),
        *(getattr(LinuxNativeRelease, key) == value for key, value in source.items()),
    )
    if execute:
        release_query = release_query.with_for_update()
    release = await session.scalar(release_query)
    checked_at = now or datetime.now(UTC)
    if campaign is None or not _active(campaign, checked_at):
        raise ValueError("The selected Linux enrollment campaign is unavailable, expired or exhausted")
    if release is None:
        raise ValueError("Exact active ALT RPM source is required in the selected provider")
    policy = linux_policy(campaign)
    if policy is None:
        raise ValueError("An existing Linux enrollment policy is required")
    allowed = policy.allowed_native_releases
    registered = set(await session.scalars(select(LinuxNativeRelease.id).where(LinuxNativeRelease.id.in_(allowed))))
    if registered != set(allowed):
        raise ValueError("The selected campaign must contain only registered RPM sources")
    scope = _campaign_scope(campaign, release.id, qualification["kit_sha256"])
    if execute and approved_scope_sha256 != scope["scope_sha256"]:
        raise ValueError("The reviewed campaign scope differs from the current enrollment authority")
    await _check_other_campaigns(session, campaign, release.id, checked_at)
    final_time = now or datetime.now(UTC)
    if final_time >= datetime.fromisoformat(qualification["valid_until"]) or not _active(campaign, final_time):
        raise ValueError("ALT qualification or approved campaign expired during the operation")

    already = release.id in allowed
    if execute and not already:
        policy = LinuxEnrollmentPolicyV1.model_validate({**policy.model_dump(), "allowed_native_releases": [*allowed, release.id]})
        campaign.policy = policy.model_dump(mode="json")
        await append_audit_event(
            session, actor_kind="operator", actor_identifier="alt-release-publisher",
            action="enrollment_campaign.release_included", object_kind="enrollment_campaign",
            object_identifier=str(campaign.id), request_id=qualification["qualification_id"],
            details={"qualification_id": qualification["qualification_id"], "kit_sha256": qualification["kit_sha256"],
                     "native_release_id": str(release.id), "scope_sha256": scope["scope_sha256"]},
            occurred_at=final_time,
        )
    return {**scope, "state": "included" if execute else "preview", "changed": execute and not already,
            "already_included": already, "use_count": campaign.use_count,
            "qualification_id": qualification["qualification_id"]}


async def _apply(database_url, args, source, qualification):
    provider = create_session_provider(database_url)
    try:
        async with provider() as session:
            if not args.execute:
                await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
            result = await include_release(session, source, qualification, args.campaign_id, execute=args.execute,
                                           approved_scope_sha256=args.scope_sha256)
            if args.execute:
                await session.commit()
            return result
    finally:
        await provider.close()


def campaign_release(args: Namespace) -> dict:
    if args.execute and (not args.scope_sha256 or not SHA256.fullmatch(args.scope_sha256)):
        raise ValueError("Execution requires the reviewed campaign scope SHA-256 from preview")
    candidate, qualification = agent_alt_qualification.require(args)
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL is required for the selected provider")
    source = {**_source(candidate), "signer_fingerprint": candidate["publisher_fingerprint"],
              "frozen_manifest_sha256": candidate["frozen_manifest_sha256"]}
    result = asyncio.run(_apply(database_url, args, source, qualification))
    return {**result, "schema_version": 1, "platform": "alt", "version": candidate["version"],
            "request_id": candidate["request_id"]}
