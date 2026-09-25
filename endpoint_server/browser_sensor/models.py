"""Immutable Browser Sensor release metadata; CRX bytes stay in artifact storage."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class BrowserSensorRelease(OwnershipRecord, Base):
    __tablename__ = "browser_sensor_releases"
    __table_args__ = (
        UniqueConstraint("extension_version", name="uq_browser_sensor_releases_version"),
        UniqueConstraint("artifact_identifier", name="uq_browser_sensor_releases_artifact"),
        CheckConstraint("protocol_version >= 1", name="ck_browser_sensor_protocol_positive"),
    )

    extension_version: Mapped[str] = mapped_column(String(32), nullable=False)
    extension_id: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol_version: Mapped[int] = mapped_column(Integer(), nullable=False)
    source_revision: Mapped[str] = mapped_column(String(40), nullable=False)
    minimum_agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact_identifier: Mapped[str] = mapped_column(String(256), nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    update_manifest_identifier: Mapped[str] = mapped_column(String(256), nullable=False)
    update_manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_identifier: Mapped[str] = mapped_column(String(256), nullable=False)
    metadata_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    built_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
