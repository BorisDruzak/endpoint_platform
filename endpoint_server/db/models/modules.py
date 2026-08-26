"""Endpoint-owned immutable module definition and version records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from endpoint_server.db.base import Base

from .common import OwnershipRecord


MODULE_VERSION_STATES = (
    "draft",
    "validation_failed",
    "validated",
    "lab_accepted",
    "published",
    "deprecated",
    "revoked",
)

MODULE_VALIDATION_RUN_STATUSES = ("succeeded", "failed")
MODULE_LIVE_TEST_STATUSES = ("passed", "failed")


class ModuleDefinition(OwnershipRecord, Base):
    __tablename__ = "module_definitions"

    module_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)


class ModuleVersion(OwnershipRecord, Base):
    __tablename__ = "module_versions"
    __table_args__ = (
        UniqueConstraint("module_definition_id", "version", name="uq_module_versions_definition_version"),
    )

    module_definition_id: Mapped[UUID] = mapped_column(ForeignKey("module_definitions.id"), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    recipe: Mapped[dict[str, object]] = mapped_column(JSON().with_variant(JSONB(), "postgresql"), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)


class ModuleValidationRun(OwnershipRecord, Base):
    """One completed static validation result with bounded diagnostic codes."""

    __tablename__ = "module_validation_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('succeeded', 'failed')",
            name="ck_module_validation_runs_status",
        ),
    )

    module_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("module_versions.id"), nullable=False
    )
    validator_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_codes: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    warning_codes: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ModuleLiveTest(OwnershipRecord, Base):
    """One lab execution acceptance result for a declared target platform."""

    __tablename__ = "module_live_tests"
    __table_args__ = (
        CheckConstraint(
            "platform IN ('linux_amd64', 'windows_amd64')",
            name="ck_module_live_tests_platform",
        ),
        CheckConstraint(
            "status IN ('passed', 'failed')",
            name="ck_module_live_tests_status",
        ),
    )

    module_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("module_versions.id"), nullable=False
    )
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    endpoint_device_id: Mapped[UUID] = mapped_column(
        ForeignKey("devices.id"), nullable=False
    )
    operation_id: Mapped[UUID] = mapped_column(
        ForeignKey("endpoint_operations.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    safe_result_snapshot: Mapped[dict[str, object]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    tested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


__all__ = [
    "MODULE_LIVE_TEST_STATUSES",
    "MODULE_VALIDATION_RUN_STATUSES",
    "MODULE_VERSION_STATES",
    "ModuleDefinition",
    "ModuleLiveTest",
    "ModuleValidationRun",
    "ModuleVersion",
]
