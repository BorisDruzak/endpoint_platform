"""Enrollment campaign, claim, and event ownership models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
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
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    allowed_cidrs: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False)
    target_platform: Mapped[str] = mapped_column(String(64), nullable=False)
    policy: Mapped[dict[str, object]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
    )
    label: Mapped[str | None] = mapped_column(String(256))
    site: Mapped[str | None] = mapped_column(String(128))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EnrollmentClaim(OwnershipRecord, Base):
    __tablename__ = "enrollment_claims"

    campaign_id: Mapped[UUID] = mapped_column(
        ForeignKey("enrollment_campaigns.id", ondelete="CASCADE"), nullable=False
    )
    enrollment_request_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("enrollment_requests.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
    )
    claim_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    claim_digest: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    installation_session_digest: Mapped[str] = mapped_column(
        String(256), nullable=False
    )
    fingerprint_digest: Mapped[str] = mapped_column(String(256), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EnrollmentRequest(OwnershipRecord, Base):
    """Auditable, digest-bound universal Windows enrollment orchestration."""

    __tablename__ = "enrollment_requests"
    __table_args__ = (
        Index("ix_enrollment_requests_expires_at", "expires_at"),
        Index("ix_enrollment_requests_status_created", "status", "created_at", "id"),
        Index(
            "uq_enrollment_requests_active_installation",
            "installation_id_digest",
            unique=True,
            postgresql_where=text(
                "status IN ('created', 'validating', 'auto_approved', "
                "'waiting_approval', 'review_required', 'claim_issued', "
                "'enrolling', 'device_registered', 'waiting_wss')"
            ),
        ),
    )

    installation_id_digest: Mapped[str] = mapped_column(String(256), nullable=False)
    fingerprint_digest: Mapped[str] = mapped_column(String(256), nullable=False)
    request_capability_digest: Mapped[str] = mapped_column(String(256), nullable=False)
    platform: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    manufacturer: Mapped[str | None] = mapped_column(String(256))
    model: Mapped[str | None] = mapped_column(String(256))
    serial: Mapped[str | None] = mapped_column(String(256))
    product_uuid: Mapped[str | None] = mapped_column(String(64))
    macs: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False, default=list
    )
    source_address: Mapped[str] = mapped_column(String(64), nullable=False)
    installer_version: Mapped[str] = mapped_column(String(128), nullable=False)
    installer_release_id: Mapped[str] = mapped_column(String(128), nullable=False)
    selected_campaign_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("enrollment_campaigns.id", ondelete="RESTRICT"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    decision_reason: Mapped[str | None] = mapped_column(String(128))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("admin_users.id", ondelete="SET NULL")
    )
    device_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EnrollmentRequestClaimEnvelope(OwnershipRecord, Base):
    """Encrypted one-claim recovery state for a capability-proven request."""

    __tablename__ = "enrollment_request_claim_envelopes"

    enrollment_request_id: Mapped[UUID] = mapped_column(
        ForeignKey("enrollment_requests.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    claim_id: Mapped[UUID] = mapped_column(
        ForeignKey("enrollment_claims.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    receipt_digest: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    fingerprint_digest: Mapped[str] = mapped_column(String(256), nullable=False)
    encrypted_token: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


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
