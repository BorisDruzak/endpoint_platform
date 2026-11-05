"""WorkTime-only browser authority, independent of OIDC employee/admin sessions."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from endpoint_server.db.base import Base
from .common import OwnershipRecord


class WorktimeLoginFlow(OwnershipRecord,Base):
    __tablename__='worktime_login_flows'
    state_digest: Mapped[str]=mapped_column(String(64),unique=True,nullable=False)
    browser_digest: Mapped[str]=mapped_column(String(64),nullable=False)
    verifier_encrypted: Mapped[str]=mapped_column(Text,nullable=False)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False)
    consumed_at: Mapped[datetime | None]=mapped_column(DateTime(timezone=True))


class HelpdeskWorktimeSession(OwnershipRecord,Base):
    __tablename__='helpdesk_worktime_sessions'
    identity_id: Mapped[UUID]=mapped_column(ForeignKey('confirmed_identities.id'),nullable=False)
    session_digest: Mapped[str]=mapped_column(String(64),unique=True,nullable=False)
    lease_encrypted: Mapped[str]=mapped_column(Text,nullable=False)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False)
    revoked_at: Mapped[datetime | None]=mapped_column(DateTime(timezone=True))
