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


@pytest.mark.parametrize("present_size", [None, 20])
def test_exact_recovery_inventory_counts_missing_or_larger_files(
    tmp_path, monkeypatch, present_size
):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from pc_agent.platform.windows import installation_provenance as provenance

    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    root = tmp_path / "Agent"
    root.mkdir()
    file = root / "old.exe"
    if present_size is not None:
        file.write_bytes(b"x" * present_size)
    package = SimpleNamespace(
        product_code="{11111111-1111-4111-8111-111111111111}",
        package_code="{22222222-2222-4222-8222-222222222222}",
        sha256="a" * 64,
        files=(SimpleNamespace(name="file", component="cmp", path="old.exe", size=5),),
        components={
            "cmp": SimpleNamespace(
                guid="{33333333-3333-4333-8333-333333333333}",
                directory="dir",
                keypath="file",
                features=("feature",),
            )
        },
    )
    authority = provenance.RecoveryCostAuthority(
        "install", ((tmp_path / "exact.msi", package),), ()
    )
    monkeypatch.setattr(provenance, "recovery_cost_authority", lambda *_: authority)
    monkeypatch.setattr(provenance, "_assert_security", lambda _: None)

    @contextmanager
    def session(_):
        yield 1

    native = SimpleNamespace(
        related=lambda: [package.product_code],
        optional_product_info=lambda *_: None,
        session=session,
        string=lambda *_: str(root),
        component=lambda *_: (-1, ""),
    )
    context = costing.RecoveryCostContext(
        SimpleNamespace(install_root=root), {"exact": "release"}
    )
    allocations, authorized = costing._recovery_rollback_allocations(
        native, tmp_path / "exact.msi", context
    )
    assert allocations == [(file, 5 if present_size is None else present_size)]
    assert authorized == frozenset({package.product_code})
    native.component = lambda *_: (3, str(root / "conflict.exe"))
    with pytest.raises(costing.MsiCostError):
        costing._recovery_rollback_allocations(native, tmp_path / "exact.msi", context)
    with pytest.raises(costing.MsiCostError):
        costing._recovery_rollback_allocations(native, tmp_path / "exact.msi", True)
    native.component = lambda *_: (-1, "")
    installer = tmp_path / "Installer"
    installer.mkdir()
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    checked = []
    monkeypatch.setattr(
        costing,
        "_trusted_cache_acls",
        lambda root, leaves: checked.append((root, leaves)),
    )
    native.optional_product_info = lambda _product, key: (
        str(installer / "missing.msi") if key == "LocalPackage" else None
    )
    assert (
        costing._recovery_rollback_allocations(native, tmp_path / "exact.msi", context)[
            0
        ]
        == allocations
    )
    assert checked == [(installer, ())]
    native.optional_product_info = lambda _product, key: (
        str(tmp_path / "outside.msi") if key == "LocalPackage" else None
    )
    with pytest.raises(costing.MsiCostError):
        costing._recovery_rollback_allocations(native, tmp_path / "exact.msi", context)
    native.optional_product_info = lambda _product, key: (
        "{99999999-9999-4999-8999-999999999999}" if key == "PackageCode" else None
    )
    with pytest.raises(costing.MsiCostError):
        costing._recovery_rollback_allocations(native, tmp_path / "exact.msi", context)


def test_restricted_native_session_has_exact_flags_actions_and_no_fallback(monkeypatch):
    from types import SimpleNamespace

    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    calls = []

    def init(*_):
        return 0

    def finish():
        calls.append(("uninitialize",))

    monkeypatch.setattr(
        costing.ctypes,
        "OleDLL",
        lambda _: SimpleNamespace(CoInitializeEx=init, CoUninitialize=finish),
    )
    native = costing._NativeMsi.__new__(costing._NativeMsi)

    def api(name, _args, *_):
        def run(*args):
            if name == "MsiOpenPackageExW":
                calls.append(("open", args[1]))
                args[2]._obj.value = 5
            elif name == "MsiDoActionW":
                calls.append(("action", args[1]))
            else:
                calls.append(("close", args[0]))
            return 0

        return run

    native.api = api
    with native.session(Path("exact.msi")) as handle:
        assert handle == 5
    assert calls == [
        ("open", 1),
        ("action", "CostInitialize"),
        ("action", "FileCost"),
        ("action", "CostFinalize"),
        ("close", 5),
        ("uninitialize",),
    ]


def test_authorized_product_never_hides_unrelated_cache_failure(tmp_path):
    from types import SimpleNamespace

    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    allowed = "{11111111-1111-4111-8111-111111111111}"
    unrelated = "{44444444-4444-4444-8444-444444444444}"
    observed = []

    def info(_name, args):
        observed.append(args[0])
        raise costing.MsiCostError()

    native = SimpleNamespace(related=lambda: [allowed, unrelated], string=info)
    with pytest.raises(costing.MsiCostError):
        costing._installed_rollback_files(native, frozenset({allowed}))
    assert observed == [unrelated]


def test_fallback_does_not_charge_retained_zip_tree(tmp_path):
    costing = importlib.import_module("pc_agent.platform.windows.msi_disk_costing")
    retained = tmp_path / "retained-zip"
    retained.mkdir()
    (retained / "core.exe").write_bytes(b"x" * 1000)
    assert costing._fallback_allocations([(tmp_path / "new.exe", 3)], [], tmp_path) == [
        (tmp_path / "new.exe", 3),
        (tmp_path, 3),
    ]


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
