"""Immutable native events and a serialized, per-device causal projection."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import event, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class InstallationEvent(OwnershipRecord, Base):
    __tablename__ = 'installation_events'
    __table_args__ = (UniqueConstraint('device_id','generation_id','sequence',name='uq_installation_event_sequence'),
        CheckConstraint('sequence BETWEEN 1 AND 2147483647',name='ck_installation_event_sequence'))
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id'), index=True)
    source_credential_id: Mapped[UUID] = mapped_column(ForeignKey('device_credentials.id'))
    generation_id: Mapped[UUID] = mapped_column()
    sequence: Mapped[int] = mapped_column(Integer)
    previous_event_id: Mapped[UUID | None] = mapped_column(ForeignKey('installation_events.id'))
    action: Mapped[str] = mapped_column(String(16))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict] = mapped_column(JSON)
    acknowledgement: Mapped[dict] = mapped_column(JSON)


class InstallationState(OwnershipRecord, Base):
    __tablename__ = 'installation_states'
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id'), unique=True)
    generation_id: Mapped[UUID] = mapped_column()
    sequence: Mapped[int] = mapped_column(Integer)
    event_id: Mapped[UUID] = mapped_column(ForeignKey('installation_events.id'))
    state: Mapped[str] = mapped_column(String(16))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    support_revision: Mapped[int | None] = mapped_column(Integer)
    support_generation: Mapped[int | None] = mapped_column(Integer)
    support_credential_id: Mapped[UUID | None] = mapped_column(ForeignKey('device_credentials.id'))
    support_auto_eligible: Mapped[bool] = mapped_column(Boolean, default=False, server_default='false')
    support_rebind_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InstallationParent(OwnershipRecord, Base):
    __tablename__ = 'installation_parents'
    enrollment_request_id: Mapped[UUID] = mapped_column(ForeignKey('enrollment_requests.id'), unique=True)
    previous_device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id'))
    removed_event_id: Mapped[UUID] = mapped_column(ForeignKey('installation_events.id'))
    approved_by: Mapped[UUID] = mapped_column(ForeignKey('admin_users.id'))


@event.listens_for(InstallationEvent, 'before_update')
@event.listens_for(InstallationEvent, 'before_delete')
@event.listens_for(InstallationParent, 'before_update')
@event.listens_for(InstallationParent, 'before_delete')
def reject_installation_history_mutation(*args):
    raise ValueError('Installation history is append-only')
