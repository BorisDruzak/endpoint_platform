"""Keep unit tests away from the installed services' fixed exclusion object."""
from uuid import uuid4
import pytest

@pytest.fixture(autouse=True)
def isolated_update_transaction(monkeypatch):
    from pc_agent.platform.windows import update_transaction
    monkeypatch.setattr(update_transaction, '_MUTEX_NAME', 'Local\\EndpointUnitTest-' + uuid4().hex)


@pytest.fixture(autouse=True)
def forbid_operator_browser_policy_registry(monkeypatch):
    """A unit/native fixture must explicitly supply an isolated registry adapter."""
    from pc_agent.platform.windows import browser_policy
    def forbidden(_self):
        pytest.fail('Test attempted the operator machine browser policy registry; inject a fake adapter')
    monkeypatch.setattr(browser_policy.WindowsPolicyRegistry, '__init__', forbidden)


@pytest.fixture(autouse=True)
def forbid_operator_openssh_servicing(monkeypatch):
    """Dependency tests must explicitly inject their own Windows FoD boundary."""
    from pc_agent.platform.windows import support_access_os
    def forbidden(*args, **kwargs):
        pytest.fail('Test attempted operator Windows servicing; inject an isolated FoD adapter')
    monkeypatch.setattr(support_access_os.WindowsFOD, 'capabilities', forbidden)
    monkeypatch.setattr(support_access_os.WindowsFOD, 'install', forbidden)


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


@pytest.fixture
def journal_test_directory(monkeypatch):
    """Isolate journal lifecycle tests from the installed machine-data namespace."""
    import os

    if os.name == "nt":
        from pc_agent.platform.windows.acl import PyWin32AclAdapter

        def prepare(acl, path, *, include_downloads):
            assert not include_downloads
            acl.protect_directory(path)

        monkeypatch.setattr(PyWin32AclAdapter, "prepare_core_update_directories", prepare)

@pytest.fixture
def mock_verified_updater_core(monkeypatch):
    """Provide explicitly positive ownership to the unrelated fake SCM tests."""
    from contextlib import nullcontext
    from hashlib import sha256

    from pc_agent.platform.windows import core_shutdown, updater_service

    def capture(paths, selector):
        if paths.current_path.read_bytes() == selector:
            return core_shutdown.CoreOwner(
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
                sha256(selector).hexdigest(), "stopped", False,
            )
        return None

    monkeypatch.setattr(updater_service, 'core_shutdown_gate', lambda _paths: nullcontext())
    monkeypatch.setattr(updater_service, 'capture_core_owner', capture)

    def require(paths, selector, owner):
        assert owner == capture(paths, selector)

    monkeypatch.setattr(updater_service, 'require_core_stopped', require)
