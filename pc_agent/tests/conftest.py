"""Keep unit tests away from the installed services' fixed exclusion object."""
from uuid import uuid4
import pytest

@pytest.fixture(autouse=True)
def isolated_update_transaction(monkeypatch):
    from pc_agent.platform.windows import update_transaction
    monkeypatch.setattr(update_transaction, '_MUTEX_NAME', 'Local\\EndpointUnitTest-' + uuid4().hex)


@pytest.fixture
def protected_update_state_root(tmp_path):
    """Source state-machine fixtures use real trusted DACLs, never an ACL bypass."""
    import os
    if os.name == 'nt':
        import win32security
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', 1)
        win32security.SetNamedSecurityInfo(str(tmp_path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, descriptor.GetSecurityDescriptorDacl(), None)
    return tmp_path
