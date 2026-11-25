"""Register a verified Windows Setup sidecar and binary in artifact storage.

Run from the repository root with DATABASE_URL and ARTIFACT_ROOT exported from the
server EnvironmentFile after migration 0023. Both the Setup EXE and MSI are
required so the two digests in the build sidecar are checked before publication.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import json
import shutil
import tempfile
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from endpoint_server.audit.service import append_audit_event
from endpoint_server.console.installer import _sha256
from endpoint_server.db.models import WindowsSetupRelease
from endpoint_server.db.session import create_session_provider
from endpoint_server.enrollment.default_campaign import include_windows_release, preview_windows_release_inclusion
from endpoint_server.setup_updates.models import SetupAssignment, SetupFleetQualification, SetupRelease
from endpoint_server.setup_updates.policy import valid_qualification
from endpoint_server.setup_updates.service import now_utc


_VERSION_RE = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$"
_SHA256_RE = r"^[0-9a-f]{64}$"
_GIT_SHA_RE = r"^[0-9a-f]{40}$"


class SetupSidecar(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^endpoint_windows_setup_release_v1$")
    version: str = Field(pattern=_VERSION_RE)
    agent_version: str = Field(pattern=_VERSION_RE)
    source_commit: str = Field(pattern=_GIT_SHA_RE)
    msi_source_commit: str = Field(pattern=_GIT_SHA_RE)
    product_code: str | None = Field(default=None,max_length=38,pattern=r'^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$')
    filename: str = Field(max_length=256)
    setup_sha256: str = Field(pattern=_SHA256_RE)
    msi_sha256: str = Field(pattern=_SHA256_RE)
    authenticode_status: str = Field(pattern=r"^(valid|unsigned|invalid)$")
    authenticode_publisher: str | None = Field(default=None, max_length=512)
    msi_authenticode_status: str = Field(pattern=r"^(valid|unsigned|invalid)$")
    msi_authenticode_publisher: str | None = Field(default=None, max_length=512)


def validate_release_inputs(sidecar: Path, setup: Path, msi: Path, msi_manifest: Path | None = None, expected_publisher: str | None = None, *, candidate_only: bool = False) -> SetupSidecar:
    if candidate_only and msi_manifest is None:
        raise ValueError('Candidate registration requires an inspected MSI manifest and expected publisher')
    if not all(path.is_file() and not path.is_symlink() for path in (sidecar, setup, msi)):
        raise ValueError("sidecar, Setup and MSI must be regular files")
    if sidecar.stat().st_size > 64 * 1024:
        raise ValueError("Setup sidecar is too large")
    metadata = SetupSidecar.model_validate_json(sidecar.read_bytes())
    if metadata.filename != f"EndpointAgentSetup-{metadata.version}-x64.exe":
        raise ValueError("Setup filename does not match release version")
    if setup.name != metadata.filename or not msi.name.lower().endswith(".msi"):
        raise ValueError("Setup or MSI filename is invalid")
    if _sha256(setup) != metadata.setup_sha256 or _sha256(msi) != metadata.msi_sha256:
        raise ValueError("Setup or MSI digest does not match sidecar")
    if metadata.authenticode_status == "valid" and not metadata.authenticode_publisher:
        raise ValueError("valid Setup signature requires a publisher")
    if metadata.msi_authenticode_status == "valid" and not metadata.msi_authenticode_publisher:
        raise ValueError("valid MSI signature requires a publisher")
    if metadata.product_code is not None:
        raise ValueError('ProductCode must come from the inspected MSI manifest')
    if msi_manifest is not None:
        if not expected_publisher or metadata.authenticode_publisher != expected_publisher or metadata.msi_authenticode_publisher != expected_publisher:
            raise ValueError('Lifecycle publication requires the expected trusted publisher for Setup and MSI')
        if not msi_manifest.is_file() or msi_manifest.is_symlink() or msi_manifest.stat().st_size > 65536:
            raise ValueError('MSI manifest must be a bounded regular file')
        manifest=json.loads(msi_manifest.read_bytes())
        if (manifest.get('schema_version') != 'endpoint_windows_release_v1' or manifest.get('package_sha256') != metadata.msi_sha256 or manifest.get('version') != metadata.agent_version or
            manifest.get('source_revision') != metadata.msi_source_commit or
            metadata.authenticode_status != 'valid' or metadata.msi_authenticode_status != 'valid'):
            raise ValueError('Inspected MSI manifest does not match signed release')
        metadata=SetupSidecar.model_validate({**metadata.model_dump(),'product_code':manifest.get('product_code')})
        if metadata.product_code is None:
            raise ValueError('Inspected MSI ProductCode is required')
    return metadata


async def _require_promotion_qualification(session, candidate: WindowsSetupRelease,
        qualification_id: UUID | None, *, lock: bool) -> tuple[SetupRelease, SetupFleetQualification]:
    if qualification_id is None:
        raise ValueError('An active native Setup qualification is required to promote a hidden candidate')
    query = (
        select(SetupFleetQualification, SetupRelease, SetupAssignment)
        .join(SetupRelease, SetupRelease.id == SetupFleetQualification.release_id)
        .join(SetupAssignment, SetupAssignment.id == SetupFleetQualification.evidence_assignment_id)
        .where(SetupFleetQualification.id == qualification_id)
    )
    if lock:
        query = query.with_for_update(of=(SetupFleetQualification, SetupAssignment))
    proof = (await session.execute(query)).one_or_none()
    if proof is None:
        raise ValueError('Native Setup qualification was not found in this provider')
    qualification, target, assignment = proof
    if (not valid_qualification(qualification, target, now_utc())
            or (target.artifact_name, target.sha256, target.version, target.msi_sha256, target.source_revision) != (
                candidate.filename, candidate.setup_sha256, candidate.agent_version,
                candidate.msi_sha256, candidate.msi_source_commit)
            or assignment.release_id != target.id or assignment.status != 'applied'
            or assignment.finished_at is None or assignment.attempt_id is None
            or assignment.source_foundation_version != qualification.source_foundation):
        raise ValueError('An active qualification for this exact Setup and its applied native source is required')
    return target, qualification


def _require_matching_metadata(existing: WindowsSetupRelease, metadata: SetupSidecar) -> None:
    if any(getattr(existing, name) != value for name, value in
           metadata.model_dump(exclude={'schema_version'}).items()):
        raise ValueError('release version already has different immutable metadata or digest')


def _verify_stored_setup(root: Path, release: WindowsSetupRelease, size: int | None) -> None:
    artifact = root / release.filename
    if (not artifact.is_file() or artifact.is_symlink() or (size is not None and artifact.stat().st_size != size)
            or _sha256(artifact) != release.setup_sha256):
        raise ValueError('Stored Setup artifact differs from the registered release')


async def _validate_promotion(session, release, root, qualification_id, *, lock):
    if release.retired_at is not None:
        raise ValueError('A retired installer cannot be promoted')
    target, qualification = await _require_promotion_qualification(session, release, qualification_id, lock=lock)
    _verify_stored_setup(root, release, target.size)
    return now_utc(qualification.expires_at)


async def preview_promotion(metadata: SetupSidecar, *, database_url: str, artifact_root: Path,
        qualification_id: UUID, default_campaign_id: UUID | None = None,
        include_in_auto_campaign: bool = True) -> dict:
    """Check the current destination without changing its catalog or enrollment."""
    root = artifact_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('ARTIFACT_ROOT is not a directory')
    provider = create_session_provider(database_url)
    try:
        async with provider() as session:
            release = await session.scalar(select(WindowsSetupRelease).where(WindowsSetupRelease.version == metadata.version))
            if release is None:
                raise ValueError('Promotion requires an existing installer candidate')
            _require_matching_metadata(release, metadata)
            expires = await _validate_promotion(session, release, root, qualification_id, lock=False)
            campaign = None
            if include_in_auto_campaign:
                campaign = await preview_windows_release_inclusion(session, release, campaign_id=default_campaign_id)
            if now_utc() > expires:
                raise ValueError('Native Setup qualification expired during preview')
            return {'release_id': str(release.id), 'download_published': release.download_published,
                    'auto_enrollment': campaign, 'qualification_expires_at': expires.isoformat()}
    finally:
        await provider.close()


async def register_release(metadata: SetupSidecar, setup: Path, *, database_url: str, artifact_root: Path,
        default_campaign_id: UUID | None = None, include_in_auto_campaign: bool = True,
        candidate_only: bool = False, promotion_qualification_id: UUID | None = None) -> WindowsSetupRelease:
    if candidate_only and promotion_qualification_id is not None:
        raise ValueError('Candidate registration cannot request promotion')
    if candidate_only and (
        metadata.product_code is None or metadata.authenticode_status != 'valid'
        or metadata.msi_authenticode_status != 'valid' or not metadata.authenticode_publisher
        or metadata.authenticode_publisher != metadata.msi_authenticode_publisher
    ):
        raise ValueError('Candidate registration requires inspected ProductCode and trusted Setup/MSI signatures')
    root = artifact_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("ARTIFACT_ROOT is not a directory")
    provider = create_session_provider(database_url)
    try:
        async with provider() as session:
            existing = await session.scalar(select(WindowsSetupRelease).where(
                WindowsSetupRelease.version == metadata.version).with_for_update())
            if existing is not None:
                _require_matching_metadata(existing, metadata)
                promoting = not candidate_only and not existing.download_published
                expires = None
                if promoting or promotion_qualification_id is not None:
                    expires = await _validate_promotion(session, existing, root, promotion_qualification_id, lock=True)
                elif not candidate_only:
                    _verify_stored_setup(root, existing, None)
                if include_in_auto_campaign:
                    await include_windows_release(session, existing, campaign_id=default_campaign_id)
                if expires is not None and now_utc() > expires:
                    raise ValueError('Native Setup qualification expired during publication')
                if promoting:
                    existing.download_published = True
                    await _audit_publication(session, existing, 'windows_setup_release.download_published',
                        include_in_auto_campaign=include_in_auto_campaign, qualification_id=promotion_qualification_id)
                await session.commit()
                return existing
            if promotion_qualification_id is not None:
                raise ValueError('Promotion requires an existing installer candidate')
            target = root / metadata.filename
            if target.exists():
                if not target.is_file() or target.is_symlink() or _sha256(target) != metadata.setup_sha256:
                    raise ValueError("artifact path is occupied by a different file")
            else:
                descriptor, temp_name = tempfile.mkstemp(prefix=".setup-release-", dir=root)
                try:
                    with os.fdopen(descriptor, "wb") as destination, setup.open("rb") as source:
                        shutil.copyfileobj(source, destination, length=1024 * 1024)
                    if _sha256(Path(temp_name)) != metadata.setup_sha256:
                        raise ValueError("staged Setup digest mismatch")
                    os.link(temp_name, target)
                finally:
                    Path(temp_name).unlink(missing_ok=True)
            release = WindowsSetupRelease(
                version=metadata.version, agent_version=metadata.agent_version,
                artifact_identifier=metadata.filename, filename=metadata.filename,
                setup_sha256=metadata.setup_sha256, msi_sha256=metadata.msi_sha256,
                source_commit=metadata.source_commit, msi_source_commit=metadata.msi_source_commit,
                authenticode_status=metadata.authenticode_status,
                authenticode_publisher=metadata.authenticode_publisher,
                msi_authenticode_status=metadata.msi_authenticode_status,
                msi_authenticode_publisher=metadata.msi_authenticode_publisher, product_code=metadata.product_code,
                download_published=not candidate_only,
            )
            session.add(release)
            await session.flush()
            if include_in_auto_campaign:
                await include_windows_release(session, release, campaign_id=default_campaign_id)
            await _audit_publication(session, release, 'windows_setup_release.registered',
                                     include_in_auto_campaign=include_in_auto_campaign)
            await session.commit()
            return release
    finally:
        await provider.close()


async def _audit_publication(session, release: WindowsSetupRelease, action: str, *,
                             include_in_auto_campaign: bool, qualification_id: UUID | None = None) -> None:
    await append_audit_event(session, actor_kind='operator', actor_identifier='windows-release-publisher',
        action=action, object_kind='windows_setup_release', object_identifier=str(release.id),
        request_id=f'publish-{release.id}', details={
            'version': release.version, 'download_published': release.download_published,
            'setup_sha256': release.setup_sha256, 'msi_sha256': release.msi_sha256,
            'source_commit': release.source_commit, 'msi_source_commit': release.msi_source_commit,
            'product_code': release.product_code, 'include_in_auto_campaign': include_in_auto_campaign,
            **({'qualification_id': str(qualification_id)} if qualification_id is not None else {}),
        })


def main() -> int:
    parser = argparse.ArgumentParser(description="Register a Windows Setup release")
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--msi", type=Path, required=True)
    parser.add_argument("--expected-publisher", help="Exact trusted Authenticode publisher subject for lifecycle publication")
    parser.add_argument("--msi-manifest", type=Path, help="Inspected manifest bound to signed MSI for installation lifecycle")
    parser.add_argument('--default-campaign-id', type=UUID)
    parser.add_argument('--candidate-only', action='store_true',
        help='Register trusted native proof and default AUTO eligibility without primary download publication')
    parser.add_argument('--promotion-qualification-id', type=UUID,
        help='Current provider qualification required to promote an existing hidden installer')
    parser.add_argument('--without-auto-enrollment', action='store_true',
        help='Explicit diagnostic publication exception; published releases normally join the default campaign')
    args = parser.parse_args()
    metadata = validate_release_inputs(args.sidecar, args.setup, args.msi, args.msi_manifest, args.expected_publisher,
                                      candidate_only=args.candidate_only or args.promotion_qualification_id is not None)
    database_url = os.environ.get("DATABASE_URL", "")
    artifact_root = os.environ.get("ARTIFACT_ROOT", "")
    if not database_url or not artifact_root:
        raise ValueError("DATABASE_URL and ARTIFACT_ROOT are required")
    release = asyncio.run(register_release(metadata, args.setup, database_url=database_url, artifact_root=Path(artifact_root),
        default_campaign_id=args.default_campaign_id, include_in_auto_campaign=not args.without_auto_enrollment,
        candidate_only=args.candidate_only, promotion_qualification_id=args.promotion_qualification_id))
    print(f"registered Windows Setup release {release.version} ({release.id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
