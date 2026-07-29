"""Administrative, service-client, and audit ownership models."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint, event
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.audit.errors import AuditMutationError
from endpoint_server.db.base import Base

from .common import OwnershipRecord


class AdminUser(OwnershipRecord, Base):
    __tablename__ = "admin_users"

    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    password_digest: Mapped[str] = mapped_column(String(256), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(128)), nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AdminSession(OwnershipRecord, Base):
    __tablename__ = "admin_sessions"

    admin_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("admin_users.id", ondelete="CASCADE"), nullable=False
    )
    session_digest: Mapped[str] = mapped_column(
        String(256), nullable=False, unique=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ServiceClient(OwnershipRecord, Base):
    __tablename__ = "service_clients"

    client_identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True
    )
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ServiceCredential(OwnershipRecord, Base):
    __tablename__ = "service_credentials"
    __table_args__ = (
        UniqueConstraint(
            "service_client_id",
            "credential_identifier",
            name="uq_service_credentials_client_identifier",
        ),
    )

    service_client_id: Mapped[UUID] = mapped_column(
        ForeignKey("service_clients.id", ondelete="CASCADE"), nullable=False
    )
    credential_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    secret_digest: Mapped[str] = mapped_column(String(256), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(128)), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(OwnershipRecord, Base):
    __tablename__ = "audit_events"

    actor_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_identifier: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    object_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    object_identifier: Mapped[str | None] = mapped_column(String(128))
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[dict[str, object]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
    )


@event.listens_for(AuditEvent, "before_update")
@event.listens_for(AuditEvent, "before_delete")
def _reject_audit_mutation(*_: object) -> None:
    raise AuditMutationError("audit events are append-only")
