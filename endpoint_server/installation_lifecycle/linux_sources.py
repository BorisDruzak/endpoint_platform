"""Immutable reviewed signed RPM sources. No agent-facing publication endpoint."""
from dataclasses import dataclass
import hashlib
from pathlib import Path
from uuid import uuid4
from sqlalchemy import CheckConstraint, DateTime, String, event, select, inspect
from sqlalchemy.orm import Mapped, mapped_column
from pydantic import Field
from endpoint_contracts.linux_installation_lifecycle import LinuxInstallationNativeProof,LinuxNativeSource
from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord
from datetime import datetime


class LinuxNativeRelease(OwnershipRecord,Base):
    __tablename__='linux_native_releases'
    __table_args__=(CheckConstraint('(user_sensor_nevra IS NULL) = (user_sensor_rpm_sha256 IS NULL)',name='ck_linux_native_sensor_pair'),)
    version: Mapped[str]=mapped_column(String(17),unique=True)
    source_revision: Mapped[str]=mapped_column(String(40))
    core_nevra: Mapped[str]=mapped_column(String(200),unique=True)
    core_rpm_sha256: Mapped[str]=mapped_column(String(64),unique=True)
    user_sensor_nevra: Mapped[str|None]=mapped_column(String(200))
    user_sensor_rpm_sha256: Mapped[str|None]=mapped_column(String(64))
    signer_fingerprint: Mapped[str]=mapped_column(String(64))
    frozen_manifest_sha256: Mapped[str]=mapped_column(String(64))
    reviewed_by: Mapped[str]=mapped_column(String(128))
    retired_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))


@event.listens_for(LinuxNativeRelease,'before_delete')
def reject_release_delete(*args):
    raise ValueError('Linux native release is immutable')


@event.listens_for(LinuxNativeRelease,'before_update')
def reject_release_rewrite(mapper,connection,target):
    changes=[attr.key for attr in inspect(target).attrs if attr.history.has_changes()]
    previous=connection.scalar(select(LinuxNativeRelease.retired_at).where(LinuxNativeRelease.id==target.id).with_for_update())
    if changes!=['retired_at'] or target.retired_at is None or previous is not None:
        raise ValueError('Linux native release is immutable; only one-way retirement is allowed')


class LinuxNativeReview(LinuxNativeSource):
    signer_fingerprint: str=Field(pattern=r'^(?:[A-F0-9]{40}|[A-F0-9]{64})$')
    frozen_manifest_sha256: str=Field(pattern=r'^[0-9a-f]{64}$')
    reviewed_by: str=Field(min_length=3,max_length=128,pattern=r'^[A-Za-z0-9_.@ -]+$')


@dataclass(frozen=True)
class VerifiedRPM:
    """Only a trusted native verifier may produce this after checking signed bytes.

    Verifier runs against an isolated RPM keyring with the independently pinned
    full publisher fingerprint, rejects unsigned/bad signatures and reads NEVRA,
    source revision and frozen manifest digest from the verified package payload.
    It must not echo caller-declared metadata as a substitute for inspection.
    """
    nevra: str
    signer_fingerprint: str
    source_revision: str
    frozen_manifest_sha256: str


async def publish_native_release(session,review:LinuxNativeReview,core_path:Path,user_sensor_path:Path|None=None,*,verify_rpm,request_id=None):
    """Privileged publisher hook; mandatory native verifier, exact signed archives.

    Callback signature: verify_rpm(path:Path, expected_full_signer:str)->VerifiedRPM.
    There is deliberately no permissive/default implementation on Windows.
    Caller owns/locks immutable input archives and commits only after review.
    """
    if not callable(verify_rpm) or (user_sensor_path is None)!=(review.user_sensor_nevra is None):
        raise ValueError('Exact native verifier and paired input archives are required')
    inputs=[(Path(core_path),review.core_nevra,review.core_rpm_sha256)]
    if user_sensor_path is not None:
        inputs.append((Path(user_sensor_path),review.user_sensor_nevra,review.user_sensor_rpm_sha256))
    for path,nevra,digest in inputs:
        if path.is_symlink() or not path.is_file():
            raise ValueError('RPM must be a regular immutable input archive')
        before=hashlib.sha256(path.read_bytes()).hexdigest()
        if before!=digest:
            raise ValueError('Signed RPM archive digest mismatch')
        proof=verify_rpm(path,review.signer_fingerprint)
        if (before!=digest or hashlib.sha256(path.read_bytes()).hexdigest()!=before or
            not isinstance(proof,VerifiedRPM) or proof!=VerifiedRPM(nevra,review.signer_fingerprint,
                review.source_revision,review.frozen_manifest_sha256)):
            raise ValueError('Signed RPM bytes or reviewed payload binding mismatch')
    values=review.model_dump()
    existing=await session.scalar(select(LinuxNativeRelease).where(LinuxNativeRelease.version==review.version).with_for_update())
    if existing:
        if existing.retired_at is not None or any(getattr(existing,k)!=v for k,v in values.items()):
            raise ValueError('Linux native version is immutable')
        return existing
    row=LinuxNativeRelease(**values);session.add(row);await session.flush()
    from endpoint_server.audit.service import append_audit_event
    await append_audit_event(session,actor_kind='admin',actor_identifier=review.reviewed_by,
        action='linux_native_release.registered',object_kind='linux_native_release',object_identifier=str(row.id),
        request_id=request_id or str(uuid4()),details=values)
    return row


async def resolve_linux_source(session,proof):
    from .service import InstallationConflict
    if not isinstance(proof,LinuxInstallationNativeProof):
        raise InstallationConflict('Linux native proof required')
    values=proof.model_dump(exclude={'exit_code'})
    row=await session.scalar(select(LinuxNativeRelease).where(LinuxNativeRelease.retired_at.is_(None),
        *(getattr(LinuxNativeRelease,key)==value for key,value in values.items())).limit(1))
    if row is None:
        raise InstallationConflict('Native source is not an exact registered Linux release')
    return row
