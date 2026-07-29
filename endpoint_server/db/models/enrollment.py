"""Enrollment campaign, claim, and event ownership models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base

from .common import OwnershipRecord


class EnrollmentCampaign(OwnershipRecord, Base):
    __tablename__ = "enrollment_campaigns"

    campaign_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    token_digest: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EnrollmentClaim(OwnershipRecord, Base):
    __tablename__ = "enrollment_claims"

    campaign_id: Mapped[UUID] = mapped_column(
        ForeignKey("enrollment_campaigns.id", ondelete="CASCADE"), nullable=False
    )
    claim_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EnrollmentEvent(OwnershipRecord, Base):
    __tablename__ = "enrollment_events"

    campaign_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("enrollment_campaigns.id", ondelete="SET NULL")
    )
    claim_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("enrollment_claims.id", ondelete="SET NULL")
    )
    event_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    remote_identifier: Mapped[str | None] = mapped_column(String(128))


class EnrollmentRetryEnvelope(OwnershipRecord, Base):
    __tablename__ = "enrollment_retry_envelopes"
    __table_args__ = (
        UniqueConstraint(
            "device_credential_id",
            name="uq_enrollment_retry_envelopes_device_credential",
        ),
        Index(
            "ix_enrollment_retry_envelopes_expires_at",
            "expires_at",
        ),
    )

    device_credential_id: Mapped[UUID] = mapped_column(
        ForeignKey("device_credentials.id", ondelete="CASCADE"), nullable=False
    )
    receipt_digest: Mapped[str] = mapped_column(
        String(256), nullable=False, unique=True
    )
    fingerprint_digest: Mapped[str] = mapped_column(String(256), nullable=False)
    encrypted_token: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
