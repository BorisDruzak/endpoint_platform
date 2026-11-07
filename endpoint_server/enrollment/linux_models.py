"""Positive source authority attached to canonical request/claim/credential rows."""
from uuid import UUID
from sqlalchemy import CheckConstraint, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column
from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class LinuxEnrollmentBinding(OwnershipRecord, Base):
    __tablename__ = 'linux_enrollment_bindings'
    __table_args__ = (CheckConstraint('(claim_id IS NULL) = (credential_id IS NULL)', name='ck_linux_enrollment_consumed_pair'),)
    enrollment_request_id: Mapped[UUID] = mapped_column(ForeignKey('enrollment_requests.id', ondelete='RESTRICT'), unique=True)
    native_release_id: Mapped[UUID] = mapped_column(ForeignKey('linux_native_releases.id', ondelete='RESTRICT'))
    claim_fingerprint_digest: Mapped[str] = mapped_column(String(64))
    claim_id: Mapped[UUID | None] = mapped_column(ForeignKey('enrollment_claims.id', ondelete='RESTRICT'), unique=True)
    credential_id: Mapped[UUID | None] = mapped_column(ForeignKey('device_credentials.id', ondelete='RESTRICT'), unique=True)
