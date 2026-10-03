"""Opt-in isolation for integration tests that execute Alembic in-process."""
import logging

import pytest


@pytest.fixture(scope="module")
def preserve_migration_loggers():
    """Snapshot before module DB fixtures; restore exact original disabled state."""
    previous = {logger: logger.disabled for logger in logging.root.manager.loggerDict.values()
                if isinstance(logger, logging.Logger)}
    try:
        yield
    finally:
        for logger, disabled in previous.items():
            logger.disabled = disabled
