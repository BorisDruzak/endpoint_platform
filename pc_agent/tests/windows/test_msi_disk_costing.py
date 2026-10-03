"""Conservative MSI fallback budgets include actual larger old rollback files."""
import importlib
from pathlib import Path
import pytest


def test_fallback_budgets_actual_old_bytes_even_when_larger_than_new(tmp_path):
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    old = tmp_path / "old.exe"
    old.write_bytes(b"old-is-larger")
    allocations = costing._fallback_allocations([(tmp_path / "new.exe", 3)], [old], tmp_path / "temp")
    assert allocations == [(tmp_path / "new.exe", 3), (old, 13), (tmp_path / "temp", 3)]


def test_fallback_rejects_unexplained_missing_installed_file(tmp_path):
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    with pytest.raises(costing.MsiCostError):
        costing._fallback_allocations([(tmp_path / "new.exe", 3)], [tmp_path / "missing.exe"], tmp_path)


def test_fallback_does_not_charge_retained_zip_tree(tmp_path):
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    retained = tmp_path / "retained-zip"
    retained.mkdir()
    (retained / "core.exe").write_bytes(b"x" * 1000)
    assert costing._fallback_allocations([(tmp_path / "new.exe", 3)], [], tmp_path) == [(tmp_path / "new.exe", 3), (tmp_path, 3)]


def test_fallback_rejects_unbounded_old_size(tmp_path, monkeypatch):
    from types import SimpleNamespace
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    path = tmp_path / "old.exe"
    path.write_bytes(b"old")
    original = Path.stat
    def details(candidate, *args, **kwargs):
        if candidate == path:
            return SimpleNamespace(st_size=2 * 1024 * 1024 * 1024 + 1, st_mode=original(candidate, *args, **kwargs).st_mode)
        return original(candidate, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", details)
    with pytest.raises(costing.MsiCostError):
        costing._fallback_allocations([(tmp_path / "new.exe", 3)], [path], tmp_path)


def test_old_inventory_rejects_different_registered_component_keypath(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    inventory = costing._Inventory("{11111111-1111-4111-8111-111111111111}",
        (("file", "component", "old.exe", 3),), {"component": ("{22222222-2222-4222-8222-222222222222}", "directory", "file")},
        {"component": ("feature",)})
    @contextmanager
    def session(_):
        yield 1
    native = SimpleNamespace(related=lambda: [inventory.product],
        string=lambda name, _: str(tmp_path / "old.msi") if name == "MsiGetProductInfoW" else str(tmp_path),
        session=session, component=lambda *_: (3, str(tmp_path / "different.exe")), feature=lambda *_: 3)
    monkeypatch.setattr(costing, "_trusted_cached_msi", lambda _: None)
    monkeypatch.setattr(costing, "_inventory", lambda _: inventory)
    with pytest.raises(costing.MsiCostError):
        costing._installed_rollback_files(native)


def test_trusted_cache_rejects_caller_file_outside_installer_root(tmp_path):
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    if costing.os.name != "nt":
        pytest.skip("native cache trust boundary")
    candidate = tmp_path / "untrusted.msi"
    candidate.write_bytes(b"untrusted")
    with pytest.raises(costing.MsiCostError):
        costing._trusted_cached_msi(candidate)


@pytest.mark.parametrize("feature_state,allowed", [(2, True), (3, False), (-1, False)])
def test_unknown_component_requires_explicit_absent_feature(tmp_path, monkeypatch, feature_state, allowed):
    from contextlib import contextmanager
    from types import SimpleNamespace
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    inventory = costing._Inventory("{11111111-1111-4111-8111-111111111111}",
        (("file", "component", "old.exe", 3),), {"component": ("{22222222-2222-4222-8222-222222222222}", "directory", "file")},
        {"component": ("retired_feature",)})
    @contextmanager
    def session(_):
        yield 1
    native = SimpleNamespace(related=lambda: [inventory.product],
        string=lambda name, _: str(tmp_path / "old.msi") if name == "MsiGetProductInfoW" else str(tmp_path),
        session=session, component=lambda *_: (-1, ""), feature=lambda *_: feature_state)
    monkeypatch.setattr(costing, "_trusted_cached_msi", lambda _: None)
    monkeypatch.setattr(costing, "_inventory", lambda _: inventory)
    if allowed:
        assert costing._installed_rollback_files(native) == []
    else:
        with pytest.raises(costing.MsiCostError):
            costing._installed_rollback_files(native)


@pytest.mark.parametrize("permission,allowed", [(0x00120089, True), (0x40000000, False)])
def test_cache_trust_accepts_inherited_read_but_rejects_untrusted_write(tmp_path, monkeypatch, permission, allowed):
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    if costing.os.name != "nt":
        pytest.skip("native cache ACL boundary")
    import win32security
    root = tmp_path / "Installer"
    root.mkdir()
    cached = root / "cache.msi"
    cached.write_bytes(b"msi")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    acl = win32security.ACL()
    acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, win32security.INHERITED_ACE,
        permission, win32security.ConvertStringSidToSid("S-1-1-0"))
    class Descriptor:
        def GetSecurityDescriptorOwner(self):
            return win32security.ConvertStringSidToSid("S-1-5-18")
        def GetSecurityDescriptorDacl(self):
            return acl
    monkeypatch.setattr(win32security, "GetNamedSecurityInfo", lambda *_: Descriptor())
    if allowed:
        costing._trusted_cached_msi(cached)
    else:
        with pytest.raises(costing.MsiCostError):
            costing._trusted_cached_msi(cached)
