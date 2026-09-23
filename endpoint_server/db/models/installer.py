"""Immutable Windows Setup release metadata; binaries remain in artifact storage."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base
from endpoint_server.db.ownership import OwnershipRecord


class WindowsSetupRelease(OwnershipRecord, Base):
    __tablename__ = "windows_setup_releases"
    __table_args__ = (
        UniqueConstraint("version", name="uq_windows_setup_releases_version"),
        UniqueConstraint("artifact_identifier", name="uq_windows_setup_releases_artifact"),
        CheckConstraint(
            "authenticode_status IN ('valid', 'unsigned', 'invalid')",
            name="ck_windows_setup_releases_signature",
        ),
        CheckConstraint(
            "msi_authenticode_status IN ('valid', 'unsigned', 'invalid')",
            name="ck_windows_setup_releases_msi_signature",
        ),
    )

    version: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(128), nullable=False)
    artifact_identifier: Mapped[str] = mapped_column(String(256), nullable=False)
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    setup_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    msi_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    msi_source_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    authenticode_status: Mapped[str] = mapped_column(String(16), nullable=False)
    authenticode_publisher: Mapped[str | None] = mapped_column(String(512))
    msi_authenticode_status: Mapped[str] = mapped_column(String(16), nullable=False)
    msi_authenticode_publisher: Mapped[str | None] = mapped_column(String(512))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
