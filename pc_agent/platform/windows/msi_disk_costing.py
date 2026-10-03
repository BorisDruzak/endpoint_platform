"""Read-only, bounded disk accounting for the canonical Endpoint MSI only.

Restricted Installer actions may resolve paths without completing component
costing. In that case count full new files, temporary extraction, and actual
installed MSI files that may require new rollback copies. Retained ZIP trees
are absent from MSI inventories and are never charged as new allocations.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
from pathlib import Path
import re
import time

from .disk_readiness import MAX_ARTIFACT_BYTES, MAX_EXPANDED_BYTES

UPGRADE_CODE = "{D4F3045C-51CF-49D9-AF9C-3AEBF206ED1F}"
_GUID = re.compile(r"^\{[0-9A-F-]{36}\}$")
_MAX_ROWS = 10_000


class MsiCostError(OSError):
    def __init__(self) -> None:
        super().__init__("MSI_COST_UNAVAILABLE")


@dataclass(frozen=True)
class _Inventory:
    product: str
    files: tuple[tuple[str, str, str, int], ...]
    components: dict[str, tuple[str, str, str]]
    features: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class RecoveryCostContext:
    paths: object
    release: dict


def _inventory(path: Path) -> _Inventory:
    import msilib  # Supported Python 3.12 Windows stdlib; Setup only.
    database = msilib.OpenDatabase(str(path), msilib.MSIDBOPEN_READONLY)
    def rows(sql, fields):
        view = database.OpenView(sql)
        view.Execute(None)
        values = []
        try:
            while record := view.Fetch():
                if len(values) >= _MAX_ROWS:
                    raise MsiCostError()
                row = tuple(record.GetInteger(i) if kind is int else record.GetString(i)
                    for i, kind in enumerate(fields, 1))
                if any(isinstance(value, str) and len(value) > 4096 for value in row):
                    raise MsiCostError()
                values.append(row)
        finally:
            view.Close()
        return values
    properties = dict(rows("SELECT `Property`, `Value` FROM `Property`", [str, str]))
    product = properties.get("ProductCode", "").upper()
    if properties.get("UpgradeCode", "").upper() != UPGRADE_CODE or not _GUID.fullmatch(product):
        raise MsiCostError()
    files = rows("SELECT `File`, `Component_`, `FileName`, `FileSize` FROM `File`", [str, str, str, int])
    components = {name: (guid.upper(), directory, keypath) for name, guid, directory, keypath in
        rows("SELECT `Component`, `ComponentId`, `Directory_`, `KeyPath` FROM `Component`", [str] * 4)}
    features: dict[str, list[str]] = {}
    for feature, component in rows("SELECT `Feature_`, `Component_` FROM `FeatureComponents`", [str, str]):
        features.setdefault(component, []).append(feature)
    total = 0
    for file_id, component, filename, size in files:
        leaf = filename.split("|")[-1]
        if (not file_id or component not in components or not leaf or leaf in {".", ".."}
            or any(character in leaf for character in '/\\:') or type(size) is not int or size < 0):
            raise MsiCostError()
        total += size
        if total > MAX_EXPANDED_BYTES:
            raise MsiCostError()
    if not files or not components:
        raise MsiCostError()
    return _Inventory(product, tuple(files), components, {key: tuple(value) for key, value in features.items()})


class _NativeMsi:
    def __init__(self):
        self.dll = ctypes.WinDLL("msi", use_last_error=True)

    def api(self, name, arguments, result=wintypes.UINT):
        function = getattr(self.dll, name)
        function.argtypes, function.restype = arguments, result
        return function

    def string(self, name, prefix) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buffer))
        function = self.api(name, [wintypes.UINT if isinstance(prefix[0], int) else wintypes.LPCWSTR,
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)])
        if function(*prefix, buffer, ctypes.byref(length)) or not buffer.value:
            raise MsiCostError()
        return buffer.value

    @contextmanager
    def session(self, path):
        ole = ctypes.OleDLL("ole32")
        ole.CoInitializeEx.argtypes, ole.CoInitializeEx.restype = [ctypes.c_void_p, wintypes.DWORD], ctypes.c_long
        ole.CoUninitialize.argtypes, ole.CoUninitialize.restype = [], None
        ole.CoInitializeEx(None, 2)
        handle = wintypes.UINT()
        opened = False
        try:
            open_package = self.api("MsiOpenPackageExW", [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.UINT)])
            if open_package(str(path), 1, ctypes.byref(handle)):
                raise MsiCostError()
            opened = True
            action = self.api("MsiDoActionW", [wintypes.UINT, wintypes.LPCWSTR])
            for name in ("CostInitialize", "FileCost", "CostFinalize"):
                if action(handle.value, name):
                    raise MsiCostError()
            yield handle.value
        finally:
            if opened:
                self.api("MsiCloseHandle", [wintypes.UINT])(handle.value)
            ole.CoUninitialize()

    def component(self, product, guid):
        buffer = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buffer))
        state = self.api("MsiGetComponentPathW", [wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)], ctypes.c_int)(product, guid, buffer, ctypes.byref(length))
        return state, buffer.value

    def optional_product_info(self, product, property_name):
        buffer = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buffer))
        code = self.api('MsiGetProductInfoW',[wintypes.LPCWSTR,wintypes.LPCWSTR,
            wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)])(product,property_name,buffer,ctypes.byref(length))
        if code in {1605,1608}:  # UNKNOWN_PRODUCT / UNKNOWN_PROPERTY only.
            return None
        if code:
            raise MsiCostError()
        return buffer.value or None

    def feature(self, product, feature):
        return self.api("MsiQueryFeatureStateW", [wintypes.LPCWSTR, wintypes.LPCWSTR], ctypes.c_int)(product, feature)

    def related(self):
        enum = self.api("MsiEnumRelatedProductsW", [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPWSTR])
        for index in range(32):
            product = ctypes.create_unicode_buffer(39)
            code = enum(UPGRADE_CODE, 0, index, product)
            if code == 259:
                return
            if code or not _GUID.fullmatch(product.value.upper()):
                raise MsiCostError()
            yield product.value.upper()
        raise MsiCostError()


def _non_reparse_chain(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise MsiCostError()
    for item in [*reversed(path.parents), path]:
        details = item.lstat()
        if item.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
            raise MsiCostError()


def _trusted_cached_msi(path: Path) -> None:
    """Accept inherited read ACLs; reject any untrusted write permission."""
    root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Installer"
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise MsiCostError() from error
    if (
        len(relative.parts) != 1
        or path.suffix.lower() != ".msi"
        or not 0 < path.stat().st_size <= MAX_ARTIFACT_BYTES
    ):
        raise MsiCostError()
    _non_reparse_chain(path)
    _trusted_cache_acls(root, (path,))


def _trusted_cache_acls(root, leaves):
    import win32security

    trusted = {"S-1-5-18", "S-1-5-32-544"}
    installer_sid, _, _ = win32security.LookupAccountName(
        None, r"NT SERVICE\TrustedInstaller"
    )
    trusted.add(win32security.ConvertSidToStringSid(installer_sid))
    # Mutating rights only; shared read/synchronize rights are legitimate.
    mutating = (
        0x00000156 | 0x00010000 | 0x00040000 | 0x00080000 | 0x40000000 | 0x10000000
    )
    for item in (root, *leaves):
        descriptor = win32security.GetNamedSecurityInfo(
            str(item),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        if (
            win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
            not in trusted
        ):
            raise MsiCostError()
        acl = descriptor.GetSecurityDescriptorDacl()
        if acl is None:
            raise MsiCostError()
        for index in range(acl.GetAceCount()):
            header, mask, sid = acl.GetAce(index)
            if header[1] & win32security.INHERIT_ONLY_ACE:
                continue
            if header[0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
                raise MsiCostError()
            if (
                mask & mutating
                and win32security.ConvertSidToStringSid(sid) not in trusted
            ):
                raise MsiCostError()


def _recovery_cache_present(path):
    """Only an exact authorized product may reuse media for a missing leaf."""
    root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Installer"
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise MsiCostError() from error
    if len(relative.parts) != 1 or path.suffix.lower() != ".msi":
        raise MsiCostError()
    try:
        path.lstat()
    except FileNotFoundError:
        _non_reparse_chain(root)
        _trusted_cache_acls(root, ())
        return False
    _trusted_cached_msi(path)
    return True


def _resolved_files(native, handle, inventory):
    directories = {}
    result = []
    for file_id, component, filename, size in inventory.files:
        guid, directory, keypath = inventory.components[component]
        if directory not in directories:
            target = Path(native.string("MsiGetTargetPathW", (handle, directory)))
            if not target.is_absolute() or ".." in target.parts:
                raise MsiCostError()
            directories[directory] = target
        result.append(
            (file_id, component, directories[directory] / filename.split("|")[-1], size)
        )
    return result


def _installed_rollback_files(native, authorized=frozenset()):
    result = []
    for product in native.related():
        if product in authorized:
            continue
        cached = Path(native.string("MsiGetProductInfoW", (product, "LocalPackage")))
        _trusted_cached_msi(cached)
        inventory = _inventory(cached)
        if inventory.product != product:
            raise MsiCostError()
        with native.session(cached) as handle:
            files = _resolved_files(native, handle, inventory)
            groups = {}
            for file_id, component, path, size in files:
                groups.setdefault(component, []).append((file_id, path))
            for component, members in groups.items():
                guid, directory, keypath = inventory.components[component]
                if not _GUID.fullmatch(guid):
                    raise MsiCostError()
                state, actual = native.component(product, guid)
                if state in {2, -7}:  # ABSENT / NOTUSED: no old payload allocation.
                    continue
                if state == -1 and inventory.features.get(component) and all(
                    native.feature(product, feature) == 2 for feature in inventory.features[component]
                ):
                    continue
                expected = next((path for file_id, path in members if file_id == keypath), None)
                if state != 3 or expected is None or Path(actual) != expected:
                    raise MsiCostError()
                result.extend(path for _, path in members)
                if len(result) > _MAX_ROWS:
                    raise MsiCostError()
    return result


def _recovery_rollback_allocations(native, package_path, context):
    from . import installation_provenance as provenance, msi_inventory

    if type(context) is not RecoveryCostContext:
        raise MsiCostError()
    authority = provenance.recovery_cost_authority(
        context.paths, package_path, context.release
    )
    if authority is None:
        raise MsiCostError()
    registered = set(native.related())
    allocations = []
    products = set()
    total = 0
    for source, package in authority.packages:
        product = package.product_code
        if product in products:
            raise MsiCostError()
        products.add(product)
        if product in registered:
            code = native.optional_product_info(product, "PackageCode")
            if code is not None and code.upper() != package.package_code:
                raise MsiCostError()
            cached = native.optional_product_info(product, "LocalPackage")
            if cached is not None:
                if _recovery_cache_present(Path(cached)):
                    actual = msi_inventory.read_package(Path(cached), package.sha256)
                    if (actual.product_code, actual.package_code) != (
                        product,
                        package.package_code,
                    ):
                        raise MsiCostError()
        inventory = _Inventory(
            product,
            tuple(
                (item.name, item.component, Path(item.path).name, item.size)
                for item in package.files
            ),
            {
                key: (item.guid, item.directory, item.keypath)
                for key, item in package.components.items()
            },
            {key: item.features for key, item in package.components.items()},
        )
        authored = {
            item.name: context.paths.install_root / item.path for item in package.files
        }
        with native.session(source) as handle:
            files = _resolved_files(native, handle, inventory)
        for file_id, component, path, size in files:
            if path != authored[file_id] or not path.is_relative_to(
                context.paths.install_root
            ):
                raise MsiCostError()
            component_info = package.components[component]
            if product in registered:
                _state, actual = native.component(product, component_info.guid)
                expected = authored.get(component_info.keypath)
                if actual and (expected is None or Path(actual) != expected):
                    raise MsiCostError()
            # Missing expected recovery destinations are bounded by exact
            # package inventory; inspect every existing ancestor and leaf.
            for item in [*reversed(path.parents), path]:
                try:
                    details = item.lstat()
                except FileNotFoundError:
                    if not item.is_relative_to(context.paths.install_root):
                        raise MsiCostError()
                    continue
                if (
                    item.is_symlink()
                    or getattr(details, "st_file_attributes", 0) & 0x400
                ):
                    raise MsiCostError()
                if item.is_relative_to(context.paths.install_root):
                    provenance._assert_security(item)
            try:
                details = path.stat()
            except FileNotFoundError:
                pass
            else:
                if not path.is_file() or details.st_nlink != 1:
                    raise MsiCostError()
                size = max(size, details.st_size)
            if type(size) is not int or size < 0:
                raise MsiCostError()
            total += size
            if total > MAX_EXPANDED_BYTES or len(allocations) >= _MAX_ROWS:
                raise MsiCostError()
            allocations.append((path, size))
    return allocations, frozenset(products)


def _fallback_allocations(new_files, old_files, temporary):
    new_total = sum(size for _, size in new_files)
    if not new_files or any(type(size) is not int or size < 0 for _, size in new_files) or new_total > MAX_EXPANDED_BYTES:
        raise MsiCostError()
    allocations = list(new_files)
    old_total = 0
    for path in dict.fromkeys(old_files):
        try:
            _non_reparse_chain(path)
            size = path.stat().st_size
            if not path.is_file() or size < 0:
                raise MsiCostError()
        except OSError as error:
            raise MsiCostError() from error
        old_total += size
        if old_total > MAX_EXPANDED_BYTES:
            raise MsiCostError()
        allocations.append((path, size))
    allocations.append((temporary, new_total))
    return allocations


def msi_disk_allocations(path: Path, *, recovery_context=None) -> list[tuple[Path, int]]:
    """Return conservative additional allocations, never installation actions."""
    if os.name != "nt":
        raise MsiCostError()
    if recovery_context is not None and type(recovery_context) is not RecoveryCostContext:
        raise MsiCostError()
    try:
        inventory = _inventory(path)
        native = _NativeMsi()
        with native.session(path) as handle:
            # CostFinalize initializes this to zero and may compute asynchronously.
            # Bounded waiting never manufactures completed component costing.
            for _ in range(8):
                if native.string("MsiGetPropertyW", (handle, "CostingComplete")) == "1":
                    break
                time.sleep(0.25)
            files = [(target, size) for _, _, target, size in _resolved_files(native, handle, inventory)]
            temporary = Path(native.string("MsiGetPropertyW", (handle, "TempFolder")))
            if not temporary.is_absolute():
                raise MsiCostError()
        recovery, authorized = ([],frozenset()) if recovery_context is None else _recovery_rollback_allocations(native,path,recovery_context)
        allocations = _fallback_allocations(files, _installed_rollback_files(native,authorized), temporary)
        allocations.extend(recovery)
        # Windows Installer's new secure database cache and script metadata.
        system_cache = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Installer"
        allocations.append((system_cache, path.stat().st_size + 16 * 1024))
        return allocations
    except MsiCostError:
        raise
    except Exception as error:
        raise MsiCostError() from error
