"""New OTA payloads must not inherit a legacy servicing directory's writers."""
from __future__ import annotations

import hashlib
import os
import shutil
import zipfile
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.platform.windows.updater_service import WindowsUpdater

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows security")

_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_SAFE = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"


def _set_policy(path, sddl):
    import win32security as security

    sd = security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    security.SetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
        | security.PROTECTED_DACL_SECURITY_INFORMATION,
        sd.GetSecurityDescriptorOwner(), None, sd.GetSecurityDescriptorDacl(), None)


def _descriptor(path):
    import win32security as security

    descriptor = security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
    )
    return bytes(memoryview(descriptor))


@pytest.fixture
def legacy_staging():
    import win32security as security
    from win32com.shell import shell, shellcon

    admins = security.ConvertStringSidToSid("S-1-5-32-544")
    assert security.CheckTokenMembership(None, admins), "native administrator token required"
    parent = Path(shell.SHGetFolderPath(0, shellcon.CSIDL_PROGRAM_FILES, 0, 0)).resolve()
    root = parent / ("EndpointStagingSecurityTest-" + uuid4().hex)
    root.mkdir()
    try:
        _set_policy(root, _SAFE)
        install = root / "install"
        install.mkdir()
        versions = install / "versions"
        versions.mkdir()
        staging = versions / "_staging"
        staging.mkdir()
        _set_policy(staging, _SAFE + f"(A;CI;FA;;;{_TRUSTED_INSTALLER})")
        from pc_agent.platform.windows.msi_inventory import _assert_registered_cache_security
        _assert_registered_cache_security(staging)
        artifact = root / "fixture.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("pc_agent.exe", b"public non-executable fixture; never run")
            archive.writestr("_internal/nested/fixture.bin", b"public extraction fixture")
        raw = artifact.read_bytes()
        pending = SimpleNamespace(artifact_path=artifact, size=len(raw),
                                  sha256=hashlib.sha256(raw).hexdigest())
        updater = object.__new__(WindowsUpdater)
        updater._paths = WindowsUpdatePaths(install, root / "updates" / "pending.json")
        yield updater, pending, staging
    finally:
        assert root.resolve().parent == parent and root.name.startswith("EndpointStagingSecurityTest-")
        assert not root.is_symlink() and not root.lstat().st_file_attributes & 0x400
        shutil.rmtree(root)


def test_new_payload_is_strict_before_first_member_and_keeps_legacy_parent(legacy_staging, monkeypatch):
    from pc_agent.platform.windows import updater_service
    from pc_agent.platform.windows.update_transaction import _assert_state_security

    updater, pending, parent = legacy_staging
    before = _descriptor(parent)
    extract = updater_service._extract_zip_member

    def checked_extract(archive, member, staging):
        _assert_state_security(staging)
        extract(archive, member, staging)

    monkeypatch.setattr(updater_service, "_extract_zip_member", checked_extract)
    staging = updater._extract_to_staging(pending)
    for path in [staging, *staging.rglob("*")]:
        _assert_state_security(path)
    assert _descriptor(parent) == before


def test_staging_name_collision_never_repairs_existing_objects(legacy_staging, monkeypatch):
    from pc_agent.platform.windows import updater_service

    updater, pending, parent = legacy_staging
    collision = parent / ("a" * 32)
    collision.mkdir()
    sentinel = collision / "sentinel.bin"
    sentinel.write_bytes(b"existing payload must stay unchanged")
    before = {path: _descriptor(path) for path in (parent, collision, sentinel)}
    monkeypatch.setattr(updater_service.uuid, "uuid4", lambda: SimpleNamespace(hex=collision.name))
    with pytest.raises(FileExistsError):
        updater._extract_to_staging(pending)
    assert sentinel.read_bytes() == b"existing payload must stay unchanged"
    assert {path: _descriptor(path) for path in before} == before
