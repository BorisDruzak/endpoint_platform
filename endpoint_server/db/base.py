"""Declarative metadata base for Endpoint Platform persistence models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for database models added by subsequent server tasks."""
