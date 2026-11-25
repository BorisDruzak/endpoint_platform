"""Personnel notification receipts survive Activity telemetry expiry."""
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class CompanionDelivery(OwnershipRecord, Base):
    __tablename__ = 'worktime_companion_deliveries'
    __table_args__ = (UniqueConstraint('request_id', name='uq_worktime_companion_request'),)
    request_id: Mapped[UUID] = mapped_column(ForeignKey('worktime_explanation_requests.id', ondelete='CASCADE'))
    device_id: Mapped[UUID] = mapped_column(ForeignKey('devices.id', ondelete='RESTRICT'))
    user_key: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(16), default='leased')
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_id: Mapped[UUID] = mapped_column(default=uuid4)
