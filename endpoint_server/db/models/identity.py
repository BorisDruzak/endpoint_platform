"""Confirmed remote identity and independent browser authority realms."""
from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from .common import OwnershipRecord


class ConfirmedIdentity(OwnershipRecord, Base):
    __tablename__ = 'confirmed_identities'
    __table_args__ = (
        UniqueConstraint('issuer', 'subject', name='uq_confirmed_identity_subject'),
        CheckConstraint("state IN ('active','revoked')", name='ck_confirmed_identity_state'),
    )
    person_id: Mapped[UUID] = mapped_column(unique=True, nullable=False)
    department_id: Mapped[UUID | None] = mapped_column()
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    ad_object_guid: Mapped[UUID] = mapped_column(unique=True, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    admin_user_id: Mapped[UUID | None] = mapped_column(ForeignKey('admin_users.id'), unique=True)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OIDCFlow(OwnershipRecord, Base):
    __tablename__ = 'oidc_flows'
    __table_args__ = (CheckConstraint("realm IN ('admin','employee')", name='ck_oidc_flow_realm'),)
    state_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    browser_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    realm: Mapped[str] = mapped_column(String(16), nullable=False)
    encrypted_material: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UpstreamSession(OwnershipRecord, Base):
    __tablename__ = 'oidc_upstream_sessions'
    __table_args__ = (CheckConstraint("realm IN ('admin','employee')", name='ck_upstream_realm'),)
    identity_id: Mapped[UUID] = mapped_column(ForeignKey('confirmed_identities.id'), nullable=False)
    realm: Mapped[str] = mapped_column(String(16), nullable=False)
    sid: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_tokens: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    achieved_acr: Mapped[str] = mapped_column(String(255),nullable=False,default='',server_default='')
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    admin_session_id: Mapped[UUID | None] = mapped_column(ForeignKey('admin_sessions.id', ondelete='CASCADE'), unique=True)


class EmployeeSession(OwnershipRecord, Base):
    __tablename__ = 'employee_sessions'
    identity_id: Mapped[UUID] = mapped_column(ForeignKey('confirmed_identities.id'), nullable=False)
    upstream_session_id: Mapped[UUID] = mapped_column(ForeignKey('oidc_upstream_sessions.id'), nullable=False)
    session_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScopedRoleGrant(OwnershipRecord, Base):
    __tablename__ = 'scoped_role_grants'
    __table_args__ = (
        CheckConstraint("role IN ('employee','manager','hr','worktime_admin','endpoint_admin','dlp_officer')", name='ck_scoped_role'),
        CheckConstraint("role != 'manager' OR department_id IS NOT NULL", name='ck_manager_department'),
    )
    identity_id: Mapped[UUID] = mapped_column(ForeignKey('confirmed_identities.id'), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    department_id: Mapped[UUID | None] = mapped_column()
    granted_by: Mapped[UUID] = mapped_column(ForeignKey('admin_users.id'), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
