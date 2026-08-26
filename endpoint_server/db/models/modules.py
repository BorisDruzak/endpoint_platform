"""Endpoint-owned immutable module definition and version records."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import ForeignKey, JSON, String, UniqueConstraint
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


__all__ = ["MODULE_VERSION_STATES", "ModuleDefinition", "ModuleVersion"]
