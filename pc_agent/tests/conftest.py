"""Keep unit tests away from the installed services' fixed exclusion object."""
from uuid import uuid4
import pytest

@pytest.fixture(autouse=True)
def isolated_update_transaction(monkeypatch):
    from pc_agent.platform.windows import update_transaction
    monkeypatch.setattr(update_transaction, '_MUTEX_NAME', 'Local\\EndpointUnitTest-' + uuid4().hex)
