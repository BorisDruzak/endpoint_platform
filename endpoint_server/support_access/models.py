from datetime import datetime
from uuid import UUID
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped,mapped_column
from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class SupportAccess(OwnershipRecord,Base):
    __tablename__='support_access'
    __table_args__=(CheckConstraint('remote_port BETWEEN 32000 AND 41999',name='ck_support_port'),)
    device_id: Mapped[UUID]=mapped_column(ForeignKey('devices.id'),unique=True,nullable=False)
    source_credential_id: Mapped[UUID]=mapped_column(ForeignKey('device_credentials.id'),nullable=False)
    tunnel_public_key: Mapped[str]=mapped_column(String(128),unique=True,nullable=False)
    host_public_key: Mapped[str]=mapped_column(String(128),unique=True,nullable=False)
    remote_port: Mapped[int]=mapped_column(Integer,unique=True,nullable=False)
    component_version: Mapped[str]=mapped_column(String(20),nullable=False)
    revision: Mapped[int]=mapped_column(Integer,nullable=False,default=1)
    generation: Mapped[int]=mapped_column(Integer,nullable=False,default=1)
    enabled: Mapped[bool]=mapped_column(Boolean,nullable=False,default=False,server_default='false')
    reset_registration_allowed: Mapped[bool]=mapped_column(Boolean,nullable=False,default=False,server_default='false')
    expires_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    operator_public_keys: Mapped[list]=mapped_column(JSON,nullable=False,default=list)
    windows_admin_username: Mapped[str|None]=mapped_column(String(64))
    installed: Mapped[bool]=mapped_column(Boolean,nullable=False,default=False)
    tunnel_connected: Mapped[bool]=mapped_column(Boolean,nullable=False,default=False)
    reported_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str|None]=mapped_column(String(64))
    access_verified_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    access_verified_by: Mapped[str|None]=mapped_column(String(128))
