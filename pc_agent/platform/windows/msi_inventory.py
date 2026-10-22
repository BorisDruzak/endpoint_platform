"""Setup and fixed-host read-only MSI package and installed ownership adapter.

Opening the database never opens an installation session or runs MSI actions.
The offline worker must not import this module.
"""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from copy import deepcopy
import os
import re
import stat
import json

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
from pathlib import Path
import uuid

from endpoint_contracts.runtime_payload import PayloadConflict, PayloadIdentity, reject_reparse_ancestors, safe_path, version_tuple

ProvenanceConflict = PayloadConflict

_PHASE_READS = ContextVar('pinned_installer_phase_msi_reads', default=None)


class _PackageReadScope:
    """Reuse pinned immutable file evidence, never native product observations."""
    def __init__(self, immutable_media_roots=()):
        self.stack = ExitStack()
        self.pins = {}
        self.values = {}
        self.pin_scopes = {}
        self.immutable_media_roots = tuple(Path(root).absolute() for root in immutable_media_roots)
        if any('..' in root.parts for root in self.immutable_media_roots):
            raise ValueError('immutable media root must be canonical')
        self.stack.callback(self.close)

    def prefetch_media(self):
        """Hash fixed package slots concurrently after pinning all inputs."""
        paths = []
        for root in self.immutable_media_roots:
            if not re.fullmatch(r'(?:msi-)?[0-9a-f]{64}', root.name):
                continue
            path = root / 'EndpointAgent.msi'
            try:
                details = path.lstat()
            except FileNotFoundError:
                continue
            if (not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
                    or getattr(details, 'st_file_attributes', 0) & 0x400
                    or not 0 < details.st_size <= MAX_PACKAGE_BYTES):
                raise ProvenanceConflict()
            if path not in paths:
                paths.append(path)
        if len(paths) > 4:
            raise ProvenanceConflict()
        for path in paths:
            self.read('prefetch-pin', path, None, lambda: None)
        if not paths:
            return
        from concurrent.futures import ThreadPoolExecutor
        # Workers only read bytes. Native queries, state and grants stay on the
        # authenticated phase thread; publish nothing until every read succeeds.
        with ThreadPoolExecutor(max_workers=min(2, len(paths))) as pool:
            digests = list(pool.map(_hash_file, paths))
        for path in paths:
            self.validate(path)
        for path, digest in zip(paths, digests):
            self.values['sha256', path, None] = digest

    def close(self):
        try:
            with ExitStack() as closing:
                for scope in self.pin_scopes.values():
                    closing.callback(scope.close)
        finally:
            self.pin_scopes.clear()
            self.pins.clear()
            self.values.clear()

    def _immutable_media(self, path):
        return (path.suffix.lower() == '.msi' and '..' not in path.parts
                and any(path.is_relative_to(root) for root in self.immutable_media_roots))

    def validate(self, path):
        from .durable_state import _copy_identity
        descriptor, before, changed = self.pins[path]
        reject_reparse_ancestors(path)
        after = os.fstat(descriptor)
        if (_copy_identity(path.lstat()) != before or _copy_identity(after) != before
                or after.st_ctime_ns != changed):
            raise ProvenanceConflict()

    def invalidate(self):
        try:
            for path in self.pins:
                self.validate(path)
        except BaseException:
            self.close()
            raise
        for path in list(self.pins):
            if not self._immutable_media(path):
                self.pin_scopes.pop(path).close()
                del self.pins[path]
        self.values = {key: value for key, value in self.values.items() if key[1] in self.pins}

    def read(self, kind, path, identity, reader):
        from .durable_state import _copy_identity, _pinned_copy_source
        path = Path(path).absolute()
        if path not in self.pins:
            if len(self.pins) >= 16:
                return reader()
            reject_reparse_ancestors(path)
            before = _copy_identity(path.lstat())
            pin_scope = ExitStack()
            try:
                descriptor = pin_scope.enter_context(_pinned_copy_source(path))
                opened = os.fstat(descriptor)
                if _copy_identity(opened) != before:
                    raise ProvenanceConflict()
            except BaseException:
                pin_scope.close()
                raise
            self.pin_scopes[path] = pin_scope
            self.pins[path] = descriptor, before, opened.st_ctime_ns
        self.validate(path)
        key = kind, path, identity
        if key not in self.values:
            if len(self.values) >= 64:
                value = reader()
                self.validate(path)
                return value
            value = reader()
            self.validate(path)
            self.values[key] = deepcopy(value)
        # Frozen dataclasses still contain mutable manifests/component maps.
        return deepcopy(self.values[key])


@contextmanager
def package_read_scope(*, immutable_media_roots=(), prefetch_media=False):
    """One authenticated helper phase; retain deny-write/delete native handles.

    Each first inventory read still hashes and validates the complete MSI.
    Each reuse checks the retained native identity and namespace. No cache survives a phase
    or applies to mutable installed product/feature/component/SCM evidence.
    POSIX lacks this Windows sharing guarantee and always performs fresh reads.
    """
    if os.name != 'nt':
        yield
        return
    scope = _PackageReadScope(immutable_media_roots)
    from .durable_state import installer_read_invalidation
    token = _PHASE_READS.set(scope)
    try:
        with scope.stack, installer_read_invalidation(scope.invalidate):
            try:
                if prefetch_media:
                    scope.prefetch_media()
                yield
            finally:
                for path in scope.pins:
                    scope.validate(path)
    finally:
        _PHASE_READS.reset(token)


def _hash_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _file_sha256(path):
    """Reuse only bytes protected by this phase's deny-write/delete handle."""
    scope = _PHASE_READS.get()
    if scope is not None:
        return scope.read('sha256', path, None, lambda: _hash_file(path))
    return _hash_file(path)


def immutable_installer_media_roots(paths, capability, phase):
    """Only owner-pinned execution media and non-writing native cache reads.

    Installer helpers never modify these input MSIs. The native engine may
    maintain its own cache during a script, so native callback phases retain
    only the execution media already pinned by the live PowerShell owner.
    """
    releases = [capability['package']]
    if 'compound' in capability:
        releases.append(capability['compound']['old']['package'])
    roots = []
    for release in releases:
        digest = release.get('package_sha256')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ProvenanceConflict()
        roots.append(paths.install_root.parent/'installer-cache'/('msi-'+digest))
    native_phases = {'msi-preflight', 'msi-enter', 'msi-complete', 'recover-enter',
                     'foundation-config', 'uninstall-finalize-preflight',
                     'uninstall-finalize-enter', 'uninstall-finalize-complete'}
    if phase not in native_phases:
        import win32api
        # Retained original media is written once before native entry. These
        # fixed digest directories are not installed payload or mutable state.
        # Native callbacks still drop them at every mutation boundary.
        roots.extend(paths.install_root.parent/'installer-state'/'packages'/release['package_sha256']
                     for release in releases)
        roots.append(Path(win32api.GetWindowsDirectory())/'Installer')
    return tuple(roots)


UPGRADE_CODE = "{D4F3045C-51CF-49D9-AF9C-3AEBF206ED1F}"
FOUNDATION_FEATURE = "EndpointAgentFeature"
RUNTIME_FEATURE = "EndpointAgentInitialRuntimeFeature"
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_ROWS = 10000
MAX_SEMANTIC_ROWS = 50000
MAX_SEMANTIC_TEXT_BYTES = 32 * 1024 * 1024
MAX_SEMANTIC_BINARY_BYTES = 128 * 1024 * 1024


@dataclass
class _SemanticBudget:
    rows: int = 0
    text: int = 0
    binary: int = 0

    def consume(self, kind, amount):
        value = getattr(self, kind) + amount
        limit = {'rows': MAX_SEMANTIC_ROWS, 'text': MAX_SEMANTIC_TEXT_BYTES,
                 'binary': MAX_SEMANTIC_BINARY_BYTES}[kind]
        if value > limit:
            raise ProvenanceConflict()
        setattr(self, kind, value)


def guid(value):
    try:
        canonical = "{" + str(uuid.UUID(value)).upper() + "}"
        if value != canonical:
            raise ValueError()
        return canonical
    except (ValueError, TypeError, AttributeError) as error:
        raise ProvenanceConflict() from error


@dataclass(frozen=True)
class Component:
    name: str
    guid: str
    directory: str
    keypath: str
    features: tuple[str, ...]


@dataclass(frozen=True)
class InstalledFile:
    name: str
    component: str
    path: str
    size: int


@dataclass(frozen=True)
class RegistryValue:
    root: int
    key: str
    name: str


@dataclass(frozen=True)
class PackageInventory:
    sha256: str
    product_code: str
    package_code: str
    version: str
    features: dict[str, int]
    components: dict[str, Component]
    files: tuple[InstalledFile, ...]
    registry: tuple[RegistryValue, ...] = ()
    services: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExpectedMsi:
    package: PackageInventory
    identity: PayloadIdentity
    manifest: dict
    contract_bytes: bytes
    foundation_files: tuple[dict, ...] = ()


FOUNDATION_EXECUTABLES = {
    'launcher.exe':('filLauncher','cmpLauncher'),
    'endpoint-agent-service.exe':('filServiceHost','cmpServiceEntrypoints'),
    'endpoint-agent-updater.exe':('filOfflineUpdater','cmpOfflineUpdater'),
    'endpoint-agent-provision.exe':('filProvisioner','cmpProvisioner'),
    'EndpointAgentTray.exe':('filEndpointAgentTray','cmpTrayCompanion'),
    'EndpointUserSensor.exe':('filEndpointUserSensor','cmpUserSensor'),
    'EndpointBrowserBridge.exe':('filEndpointBrowserBridge','cmpBrowserBridge'),
    'EndpointBrowserPolicy.exe':('filEndpointBrowserPolicy','cmpBrowserPolicyService'),
}


def _foundation_records(value):
    if not isinstance(value,(list,tuple)) or len(value)!=len(FOUNDATION_EXECUTABLES): raise ProvenanceConflict()
    found=set()
    for row in value:
        if (not isinstance(row,dict) or set(row)!={'path','file','component','size','sha256'}
            or not isinstance(row['path'],str) or row['path'] in found
            or row['path'] not in FOUNDATION_EXECUTABLES
            or (row['file'],row['component'])!=FOUNDATION_EXECUTABLES[row['path']]
            or type(row['size']) is not int or not 0<row['size']<=1024*1024*1024
            or not isinstance(row['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',row['sha256'])):
            raise ProvenanceConflict()
        found.add(row['path'])
    return tuple(value)


@contextmanager
def verified_foundation_bytes(expected,install_root):
    """Hold each exact immutable foundation executable against substitution."""
    from . import durable_state
    from .update_transaction import _assert_state_security
    from endpoint_contracts.runtime_payload import reject_reparse_ancestors
    rows=_foundation_records(expected.foundation_files)
    reject_reparse_ancestors(install_root)
    _assert_state_security(install_root)
    with ExitStack() as stack:
        identities=[]
        for row in rows:
            path=install_root/row['path']
            reject_reparse_ancestors(path);_assert_state_security(path)
            before=durable_state._copy_identity(path.lstat())
            descriptor=stack.enter_context(durable_state._pinned_copy_source(path))
            opened=os.fstat(descriptor)
            if durable_state._copy_identity(opened)!=before: raise ProvenanceConflict()
            durable_state._verify_copy_bytes(descriptor,row['size'],row['sha256'])
            identities.append((path,descriptor,before,opened.st_ctime_ns))
        yield
        for path,descriptor,before,changed in identities:
            after=os.fstat(descriptor)
            if (durable_state._copy_identity(path.lstat())!=before or durable_state._copy_identity(after)!=before
                or after.st_ctime_ns!=changed): raise ProvenanceConflict()


def read_expected_package(path: Path, release: dict) -> ExpectedMsi:
    scope = _PHASE_READS.get()
    if scope is not None and isinstance(release, dict) and all(
            isinstance(key, str) and isinstance(value, str) for key, value in release.items()):
        return scope.read('expected', path, tuple(sorted(release.items())),
                          lambda: _read_expected_package(path, release))
    return _read_expected_package(path, release)


def _read_expected_package(path: Path, release: dict) -> ExpectedMsi:
    from endpoint_contracts.runtime_payload import read_json, bind_contract, manifest_files
    fields = {'schema_version','version','source_revision','package_sha256','product_code','initial_runtime_tree_sha256'}
    if set(release) != fields or release['schema_version'] != 'endpoint_windows_release_v1':
        raise ProvenanceConflict()
    package = read_package(path, release['package_sha256'])
    if package.product_code != release['product_code'] or package.version != release['version']:
        raise ProvenanceConflict()
    value = read_json(read_binary(path, 'EndpointInitialRuntimeInventory', maximum=8*1024*1024), 8*1024*1024)
    if set(value) != {'schema_version','manifest','contract_bytes','foundation_files'} or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ProvenanceConflict()
    try:
        contract_bytes = bytes.fromhex(value['contract_bytes'])
    except (ValueError, TypeError) as error:
        raise ProvenanceConflict() from error
    files = manifest_files(value['manifest'])
    identity = bind_contract(value['manifest'], files, contract_bytes)
    if (identity.minimum_launcher_version is not None
        and version_tuple(identity.minimum_launcher_version) > version_tuple(package.version)):
        raise ProvenanceConflict()
    original_tree = hashlib.sha256()
    original_names = sorted(('endpoint_agent_core.exe' if item.path == 'pc_agent.exe' else item.path, item.size, item.sha256) for item in files)
    for name, size, digest in original_names:
        original_tree.update(f'{name}\0{size}\0{digest}\n'.encode())
    if identity.source_revision != release['source_revision'] or original_tree.hexdigest() != release['initial_runtime_tree_sha256']:
        raise ProvenanceConflict()
    prefix = f'versions/{identity.version}/'
    runtime_files = {item.path[len(prefix):]:item for item in package.files if item.path.startswith(prefix)}
    expected_names = {item.path for item in files} | {'endpoint-update-manifest.json', '.endpoint-msi-runtime.json'}
    if set(runtime_files) != expected_names or package.features.get(RUNTIME_FEATURE) != 1:
        raise ProvenanceConflict()
    for item in runtime_files.values():
        if package.components[item.component].features != (RUNTIME_FEATURE,):
            raise ProvenanceConflict()
    for item in files:
        if runtime_files[item.path].size != item.size:
            raise ProvenanceConflict()
    foundation=_foundation_records(value['foundation_files'])
    actual={item.path:item for item in package.files if not item.path.startswith('versions/') and item.path.lower().endswith('.exe')}
    if set(actual)!=set(FOUNDATION_EXECUTABLES): raise ProvenanceConflict()
    for row in foundation:
        item=actual[row['path']]
        if (item.name!=row['file'] or item.component!=row['component'] or item.size!=row['size']
            or package.components[item.component].features!=(FOUNDATION_FEATURE,)):
            raise ProvenanceConflict()
    return ExpectedMsi(package, identity, value['manifest'], contract_bytes,foundation)


def validate_native_selector(raw: bytes, expected: ExpectedMsi) -> None:
    """Validate the successor identity, independently of JSON formatting."""
    from endpoint_contracts.runtime_payload import read_json
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 4096:
        raise ProvenanceConflict()
    value = read_json(raw, 4096)
    if value != {'schema_version': 1, 'version': expected.identity.version,
                 'source_revision': expected.identity.source_revision} or type(value.get('schema_version')) is not int:
        raise ProvenanceConflict()


def read_native_selector(path: Path, expected: ExpectedMsi) -> bytes:
    """Extract exact authored bytes from the pinned successor package only."""
    raw = read_binary(path, 'EndpointNativeCurrentSelector', maximum=4096)
    validate_native_selector(raw, expected)
    files = [item for item in expected.package.files if item.path == 'current.json']
    if (len(files) != 1 or files[0].name != 'filCurrentSelector'
        or files[0].component != 'cmpCurrentSelector' or files[0].size != len(raw)):
        raise ProvenanceConflict()
    return raw


def _rows(database, sql, kinds):
    view = database.OpenView(sql)
    view.Execute(None)
    result = []
    try:
        while record := view.Fetch():
            if len(result) >= MAX_ROWS:
                raise ProvenanceConflict()
            row = tuple(record.GetInteger(index) if kind is int else record.GetString(index)
                for index, kind in enumerate(kinds, 1))
            if any(isinstance(item, str) and len(item) > 4096 for item in row):
                raise ProvenanceConflict()
            result.append(row)
    finally:
        view.Close()
    return result


def read_package(path: Path, expected_sha256: str) -> PackageInventory:
    scope = _PHASE_READS.get()
    if scope is not None and isinstance(expected_sha256, str):
        return scope.read('package', path, expected_sha256,
                          lambda: _read_package(path, expected_sha256))
    return _read_package(path, expected_sha256)


def _read_package(path: Path, expected_sha256: str) -> PackageInventory:
    import msilib
    try:
        reject_reparse_ancestors(path)
        before = path.stat()
        if before.st_nlink != 1 or not 0 < before.st_size <= MAX_PACKAGE_BYTES:
            raise ProvenanceConflict()
        digest = _file_sha256(path)
        if digest != expected_sha256:
            raise ProvenanceConflict()
        database = msilib.OpenDatabase(str(path), msilib.MSIDBOPEN_READONLY)
        properties = dict(_rows(database, 'SELECT `Property`, `Value` FROM `Property`', [str, str]))
        if properties.get('UpgradeCode') != UPGRADE_CODE:
            raise ProvenanceConflict()
        product = guid(properties['ProductCode'])
        version = properties['ProductVersion']; version_tuple(version)
        package_value = database.GetSummaryInformation(0).GetProperty(9)
        # CPython 3.12 _msi returns summary VT_LPSTR as bytes.
        package = guid(package_value.decode('ascii') if isinstance(package_value, bytes) else package_value)
        features = dict(_rows(database, 'SELECT `Feature`, `Level` FROM `Feature`', [str, int]))
        if FOUNDATION_FEATURE not in features:
            raise ProvenanceConflict()
        memberships = {}
        for feature, component in _rows(database, 'SELECT `Feature_`, `Component_` FROM `FeatureComponents`', [str, str]):
            if feature not in features:
                raise ProvenanceConflict()
            memberships.setdefault(component, []).append(feature)
        components = {name: Component(name, guid(component_id), directory, keypath, tuple(sorted(memberships.get(name, []))))
            for name, component_id, directory, keypath in _rows(database,
                'SELECT `Component`, `ComponentId`, `Directory_`, `KeyPath` FROM `Component`', [str]*4)}
        directories = {name: (parent, default) for name, parent, default in _rows(database,
            'SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`', [str]*3)}
        def relative(directory):
            parts, visited = [], set()
            while directory != 'INSTALLFOLDER':
                if directory in visited or directory not in directories:
                    raise ProvenanceConflict()
                visited.add(directory)
                directory, default = directories[directory]
                leaf = default.split(':')[0].split('|')[-1]
                if leaf != '.':
                    parts.append(safe_path(leaf))
            return '/'.join(reversed(parts))
        files, aliases = [], set()
        for name, component, filename, size in _rows(database,
            'SELECT `File`, `Component_`, `FileName`, `FileSize` FROM `File`', [str,str,str,int]):
            owner = components[component]
            folder = relative(owner.directory)
            leaf = safe_path(filename.split('|')[-1])
            location = safe_path(f'{folder}/{leaf}' if folder else leaf)
            if size < 0 or location.casefold() in aliases or not owner.features:
                raise ProvenanceConflict()
            aliases.add(location.casefold())
            files.append(InstalledFile(name, component, location, size))
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ProvenanceConflict()
        if not files:
            raise ProvenanceConflict()
        registry=tuple(RegistryValue(root,key,name) for root,key,name in _rows(database,
            'SELECT `Root`, `Key`, `Name` FROM `Registry`',[int,str,str]))
        services=tuple(name for (name,) in _rows(database,'SELECT `Name` FROM `ServiceInstall`',[str]))
        if (any(row.root!=2 or not row.key or '[' in row.key or ']' in row.key or row.name in {'+','-','*'} for row in registry)
            or any(not name or any(char in name for char in '[]/\\') for name in services)):
            raise ProvenanceConflict()
        return PackageInventory(digest, product, package, version, features, components, tuple(files),registry,services)
    except (OSError, ValueError, KeyError, TypeError, msilib.MSIError) as error:
        raise ProvenanceConflict() from error


class NativeMsi:
    def __init__(self):
        self.dll = ctypes.WinDLL('msi', use_last_error=True)

    def _api(self, name, arguments, result=ctypes.c_int):
        method = getattr(self.dll, name)
        method.argtypes, method.restype = arguments, result
        return method

    def product(self, code):
        return self._api('MsiQueryProductStateW', [wintypes.LPCWSTR])(code)

    def property(self, code, name):
        value=self.product_metadata(code,name)
        if not value:
            raise ProvenanceConflict()
        return value

    def product_metadata(self, code, name):
        """Empty metadata differs from an unavailable native query."""
        output = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(output))
        result = self._api('MsiGetProductInfoW', [wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)])(code, name, output, ctypes.byref(length))
        if result:
            raise ProvenanceConflict()
        return output.value

    def related_products(self, upgrade_code):
        """Enumerate the actual current-user/machine upgrade family, bounded."""
        upgrade_code=guid(upgrade_code)
        query=self._api('MsiEnumRelatedProductsW',[wintypes.LPCWSTR,wintypes.DWORD,
            wintypes.DWORD,wintypes.LPWSTR],wintypes.UINT)
        products=set()
        for index in range(1024):
            output=ctypes.create_unicode_buffer(39)
            result=query(upgrade_code,0,index,output)
            if result==259:
                return tuple(sorted(products))
            if result:
                raise ProvenanceConflict()
            product=guid(output.value)
            if product in products:
                raise ProvenanceConflict()
            products.add(product)
        raise ProvenanceConflict()

    def has_patches(self, product_code):
        """Any applied patch blocks exact immutable-package admission."""
        patch=ctypes.create_unicode_buffer(39)
        transforms=ctypes.create_unicode_buffer(32768)
        length=wintypes.DWORD(len(transforms))
        result=self._api('MsiEnumPatchesW',[wintypes.LPCWSTR,wintypes.DWORD,
            wintypes.LPWSTR,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)],wintypes.UINT)(
                guid(product_code),0,patch,transforms,ctypes.byref(length))
        if result==259:
            return False
        if result in {0,234}:
            return True
        raise ProvenanceConflict()

    def _record_text(self,record,field,budget):
        output=ctypes.create_unicode_buffer(32768);length=wintypes.DWORD(len(output))
        if self._api('MsiRecordGetStringW',[wintypes.UINT,wintypes.UINT,wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD)],wintypes.UINT)(record,field,output,ctypes.byref(length)):
            raise ProvenanceConflict()
        value=output.value
        # Include an allocation allowance even for empty/null fields.
        budget.consume('text',len(value.encode('utf-8'))+64)
        return value

    def _record_binary(self,record,field,budget):
        digest=hashlib.sha256();total=0;buffer=ctypes.create_string_buffer(65536)
        read=self._api('MsiRecordReadStream',[wintypes.UINT,wintypes.UINT,ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD)],wintypes.UINT)
        while True:
            length=wintypes.DWORD(len(buffer))
            if read(record,field,buffer,ctypes.byref(length)) or length.value>len(buffer):raise ProvenanceConflict()
            if not length.value:return total,digest.hexdigest()
            total+=length.value
            if total>64*1024*1024:raise ProvenanceConflict()
            budget.consume('binary',length.value)
            digest.update(buffer.raw[:length.value])

    def _database_rows(self,database,table,budget,*,hash_rows=False):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,71}',table):raise ProvenanceConflict()
        view=wintypes.UINT();close=self._api('MsiCloseHandle',[wintypes.UINT],wintypes.UINT)
        if self._api('MsiDatabaseOpenViewW',[wintypes.UINT,wintypes.LPCWSTR,ctypes.POINTER(wintypes.UINT)],wintypes.UINT)(
            database,f'SELECT * FROM `{table}`',ctypes.byref(view)):raise ProvenanceConflict()
        try:
            schema=[]
            fields=self._api('MsiRecordGetFieldCount',[wintypes.UINT],wintypes.UINT)
            for kind in (0,1):
                info=wintypes.UINT()
                if self._api('MsiViewGetColumnInfo',[wintypes.UINT,ctypes.c_int,ctypes.POINTER(wintypes.UINT)],wintypes.UINT)(
                    view,kind,ctypes.byref(info)):raise ProvenanceConflict()
                try:
                    count=fields(info)
                    if not 0<count<=64:raise ProvenanceConflict()
                    schema.append(tuple(self._record_text(info,index,budget) for index in range(1,count+1)))
                finally:close(info)
            if len(schema[0])!=len(schema[1]):raise ProvenanceConflict()
            keys=()
            if table not in {'_Tables','_Columns'}:
                info=wintypes.UINT()
                if self._api('MsiDatabaseGetPrimaryKeysW',[wintypes.UINT,wintypes.LPCWSTR,
                    ctypes.POINTER(wintypes.UINT)],wintypes.UINT)(database,table,ctypes.byref(info)):
                    raise ProvenanceConflict()
                try:
                    count=fields(info)
                    if not 0<count<=len(schema[0]):raise ProvenanceConflict()
                    if self._record_text(info,0,budget)!=table:raise ProvenanceConflict()
                    keys=tuple(self._record_text(info,index,budget) for index in range(1,count+1))
                    if len(set(keys))!=len(keys) or any(key not in schema[0] for key in keys):raise ProvenanceConflict()
                finally:close(info)
            schema.append(keys)
            if self._api('MsiViewExecute',[wintypes.UINT,wintypes.UINT],wintypes.UINT)(view,0):raise ProvenanceConflict()
            rows=[]
            for _ in range(100000):
                record=wintypes.UINT()
                result=self._api('MsiViewFetch',[wintypes.UINT,ctypes.POINTER(wintypes.UINT)],wintypes.UINT)(view,ctypes.byref(record))
                if result==259:return schema,rows
                if result:raise ProvenanceConflict()
                try:
                    budget.consume('rows',1)
                    if fields(record)!=len(schema[1]):raise ProvenanceConflict()
                    values=[]
                    for index,column in enumerate(schema[1],1):
                        if self._api('MsiRecordIsNull',[wintypes.UINT,wintypes.UINT],wintypes.BOOL)(record,index):
                            budget.consume('text',64);values.append(('null',))
                        elif column.lower().startswith('v'):
                            budget.consume('text',64);values.append(('binary',self._record_binary(record,index,budget)))
                        else:values.append(('text',self._record_text(record,index,budget)))
                    row=tuple(values)
                    # Retain fixed-size row digests, not rows plus their JSON copies.
                    rows.append(hashlib.sha256(json.dumps(row,ensure_ascii=False,
                        separators=(',',':')).encode()).digest() if hash_rows else row)
                finally:close(record)
            raise ProvenanceConflict()
        finally:
            self._api('MsiViewClose',[wintypes.UINT],wintypes.UINT)(view);close(view)

    def database_semantics(self,path):
        """Read all persistent MSI table/schema/binary semantics, never actions.

        Media cabinet streams are not table values and may be omitted by native
        caching. Applied transforms/patches and product context need their own
        admission checks; this method supplies no replacement authority.
        """
        scope = _PHASE_READS.get()
        if scope is not None:
            return scope.read('database-semantics', path, None,
                              lambda: self._read_database_semantics(path))
        return self._read_database_semantics(path)

    def _read_database_semantics(self,path):
        database=wintypes.UINT();path=Path(path);before=path.stat()
        if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=512*1024*1024:raise ProvenanceConflict()
        if self._api('MsiOpenDatabaseW',[wintypes.LPCWSTR,ctypes.c_void_p,ctypes.POINTER(wintypes.UINT)],wintypes.UINT)(
            str(path),None,ctypes.byref(database)):raise ProvenanceConflict()
        try:
            budget=_SemanticBudget()
            _,rows=self._database_rows(database,'_Tables',budget)
            names=[row[0][1] for row in rows]
            if not names or len(names)>1024 or len(set(names))!=len(names):raise ProvenanceConflict()
            result={}
            for table in names:
                schema,rows=self._database_rows(database,table,budget,hash_rows=True)
                digest=hashlib.sha256(json.dumps(schema,ensure_ascii=False,separators=(',',':')).encode())
                digest.update(b'\x00')
                for row in sorted(rows):digest.update(row)
                result[table]=digest.hexdigest()
        finally:self._api('MsiCloseHandle',[wintypes.UINT],wintypes.UINT)(database)
        after=path.stat()
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise ProvenanceConflict()
        return result

    def feature(self, product, feature):
        return self._api('MsiQueryFeatureStateW', [wintypes.LPCWSTR, wintypes.LPCWSTR])(product, feature)

    def component(self, product, component):
        output = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(output))
        state = self._api('MsiGetComponentPathW', [wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)])(product, component, output, ctypes.byref(length))
        return state, output.value

    def resources_absent(self,package):
        """Only names in the authenticated per-machine x64 MSI inventory."""
        import winreg
        import win32service
        for row in package.registry:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,row.key,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as key:
                    winreg.QueryValueEx(key,row.name or None)
            except FileNotFoundError:
                continue
            return False
        manager=win32service.OpenSCManager(None,None,win32service.SC_MANAGER_CONNECT)
        try:
            for name in package.services:
                try:
                    service=win32service.OpenService(manager,name,win32service.SERVICE_QUERY_STATUS)
                except Exception as error:
                    if getattr(error,'winerror',None)==1060: continue
                    raise
                win32service.CloseServiceHandle(service)
                return False
        finally:
            win32service.CloseServiceHandle(manager)
        return True


def read_binary(path: Path, name: str, *, maximum: int) -> bytes:
    """Read a fixed caller-selected stream from a previously pinned MSI database."""
    if name not in {'EndpointInstallerHost', 'EndpointInitialRuntimeInventory', 'EndpointNativeCurrentSelector'} or not 0 < maximum <= MAX_PACKAGE_BYTES:
        raise ProvenanceConflict()
    api = NativeMsi()
    database, view, record = wintypes.UINT(), wintypes.UINT(), wintypes.UINT()
    close = api._api('MsiCloseHandle', [wintypes.UINT])
    try:
        if api._api('MsiOpenDatabaseW', [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(wintypes.UINT)])(
            str(path), None, ctypes.byref(database)):
            raise ProvenanceConflict()
        query = f"SELECT `Data` FROM `Binary` WHERE `Name` = '{name}'"
        if api._api('MsiDatabaseOpenViewW', [wintypes.UINT, wintypes.LPCWSTR, ctypes.POINTER(wintypes.UINT)])(
            database.value, query, ctypes.byref(view)):
            raise ProvenanceConflict()
        if api._api('MsiViewExecute', [wintypes.UINT, wintypes.UINT])(view.value, 0):
            raise ProvenanceConflict()
        if api._api('MsiViewFetch', [wintypes.UINT, ctypes.POINTER(wintypes.UINT)])(view.value, ctypes.byref(record)):
            raise ProvenanceConflict()
        stream = api._api('MsiRecordReadStream', [wintypes.UINT, wintypes.UINT, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)])
        chunks, total = [], 0
        while True:
            buffer = ctypes.create_string_buffer(min(65536, maximum + 1 - total))
            size = wintypes.DWORD(len(buffer))
            if stream(record.value, 1, buffer, ctypes.byref(size)):
                raise ProvenanceConflict()
            if not size.value:
                break
            total += size.value
            if total > maximum:
                raise ProvenanceConflict()
            chunks.append(buffer.raw[:size.value])
        if not total:
            raise ProvenanceConflict()
        return b''.join(chunks)
    finally:
        for handle in (record, view, database):
            if handle.value:
                close(handle.value)


def _assert_registered_cache_security(path):
    """Native MSI cache permits only privileged Windows servicing writers."""
    import win32security as security
    trusted={'S-1-5-18','S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}
    sd=security.GetNamedSecurityInfo(str(path),security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION|security.DACL_SECURITY_INFORMATION)
    owner=sd.GetSecurityDescriptorOwner();dacl=sd.GetSecurityDescriptorDacl()
    if owner is None or security.ConvertSidToStringSid(owner) not in trusted or dacl is None:
        raise ProvenanceConflict()
    for index in range(dacl.GetAceCount()):
        ace=dacl.GetAce(index)
        if len(ace)!=3 or ace[0][0]!=security.ACCESS_ALLOWED_ACE_TYPE:
            raise ProvenanceConflict()
        if not ace[0][1]&security.INHERIT_ONLY_ACE and ace[1]&0x500D0156 and security.ConvertSidToStringSid(ace[2]) not in trusted:
            raise ProvenanceConflict()


def verify_registered_cache(original_path,package,*,native=None):
    """Compare the protected native cache to exact original media, read only.

    No cached path is returned or executed. Native target registration/context
    and the later actual detected-target set remain separate required checks.
    """
    import win32api
    from . import durable_state
    from .installer_fence import assert_namespace_security
    native=native or NativeMsi()
    original_path=Path(original_path)
    windows=Path(win32api.GetWindowsDirectory())
    cache_root=windows/'Installer'
    cached=Path(native.property(package.product_code,'LocalPackage'))
    if not cached.is_absolute() or cached.parent!=cache_root or ':' in cached.name or cached.suffix.lower()!='.msi':
        raise ProvenanceConflict()
    try:assert_namespace_security(cached)
    except ValueError as error:raise ProvenanceConflict() from error
    for path in (windows,cache_root,cached):
        reject_reparse_ancestors(path);_assert_registered_cache_security(path)
    reject_reparse_ancestors(original_path)
    with ExitStack() as stack:
        identities=[];descriptors={}
        for path in (original_path,cached):
            before=durable_state._copy_identity(path.lstat())
            if not 0<before[2]<=MAX_PACKAGE_BYTES:raise ProvenanceConflict()
            descriptor=stack.enter_context(durable_state._pinned_copy_source(path))
            opened=os.fstat(descriptor)
            if durable_state._copy_identity(opened)!=before:raise ProvenanceConflict()
            identities.append((path,descriptor,before,opened.st_ctime_ns));descriptors[path]=descriptor
        if _file_sha256(original_path) != package.sha256:raise ProvenanceConflict()
        registered=read_package(cached,_file_sha256(cached))
        if any(getattr(registered,key)!=getattr(package,key) for key in ('product_code','package_code','version')):
            raise ProvenanceConflict()
        if native.database_semantics(original_path)!=native.database_semantics(cached):raise ProvenanceConflict()
        for path,descriptor,before,changed in identities:
            after=os.fstat(descriptor)
            if (durable_state._copy_identity(path.lstat())!=before or durable_state._copy_identity(after)!=before
                or after.st_ctime_ns!=changed):raise ProvenanceConflict()
        for path in (windows,cache_root,cached):
            reject_reparse_ancestors(path);_assert_registered_cache_security(path)
        try:assert_namespace_security(cached)
        except ValueError as error:raise ProvenanceConflict() from error


def installed_feature_state(package: PackageInventory, *, native=None) -> str:
    native = native or NativeMsi()
    if (native.product(package.product_code) != 5
        or native.property(package.product_code, 'VersionString') != package.version
        or native.property(package.product_code, 'PackageCode') != package.package_code
        or native.feature(package.product_code, FOUNDATION_FEATURE) != 3):
        raise ProvenanceConflict()
    if RUNTIME_FEATURE not in package.features:
        return 'complete'
    state = native.feature(package.product_code, RUNTIME_FEATURE)
    if state not in (2, 3):
        raise ProvenanceConflict()
    return 'complete' if state == 3 else 'foundation_only'


def verify_installed(package: PackageInventory, install_root: Path, *, native=None) -> None:
    native = native or NativeMsi()
    if installed_feature_state(package, native=native) != 'complete':
        raise ProvenanceConflict()
    _verify_components(package,install_root,native,package.components.values())


def verify_foundation(package: PackageInventory, install_root: Path, *, native=None,expected=None) -> str:
    native=native or NativeMsi()
    state=installed_feature_state(package,native=native)
    _verify_components(package,install_root,native,
        (component for component in package.components.values() if FOUNDATION_FEATURE in component.features))
    if expected is not None:
        with verified_foundation_bytes(expected,install_root): pass
    return state


def verify_replaced_product(old: PackageInventory, new: PackageInventory, install_root: Path, *, native=None) -> None:
    """Old registration is absent; shared resources belong to the exact successor."""
    native=native or NativeMsi()
    if old.product_code==new.product_code or native.product(old.product_code)!=-1:
        raise ProvenanceConflict()
    for feature in old.features:
        if native.feature(old.product_code,feature)!=-1:
            raise ProvenanceConflict()
    for component in old.components.values():
        state,location=native.component(old.product_code,component.guid)
        if state!=-1 or location:
            raise ProvenanceConflict()
    verify_installed(new,install_root,native=native)


def verify_uninstalled(package: PackageInventory, install_root: Path, *, native=None) -> dict:
    """Absence evidence is a postcondition, never an execution barrier."""
    native=native or NativeMsi()
    if native.product(package.product_code)!=-1: raise ProvenanceConflict()
    try:
        install_root.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ProvenanceConflict()
    digest=hashlib.sha256()
    for feature in sorted(package.features):
        if native.feature(package.product_code,feature)!=-1: raise ProvenanceConflict()
        digest.update(f'feature\0{feature}\0absent\n'.encode())
    for component in sorted(package.components.values(),key=lambda row:row.guid):
        state,location=native.component(package.product_code,component.guid)
        if state!=-1 or location: raise ProvenanceConflict()
        digest.update(f'component\0{component.guid}\0absent\n'.encode())
    if not native.resources_absent(package): raise ProvenanceConflict()
    return {'product_code':package.product_code,'component_count':len(package.components),
        'feature_count':len(package.features),'ownership_sha256':digest.hexdigest(),
        'registry_count':len(package.registry),'service_count':len(package.services),'install_root_absent':True}


def _verify_components(package,install_root,native,components):
    components = tuple(components)
    features = sorted({feature for component in components for feature in component.features})
    # MsiQueryFeatureState opens the product's feature configuration. Repeat it
    # at the verification boundaries, rather than once per component sharing
    # that feature. Component state/keypath checks remain individual and live.
    for feature in features:
        if native.feature(package.product_code, feature) != 3:
            raise ProvenanceConflict()
    files = {item.name: item for item in package.files}
    for component in components:
        state, location = native.component(package.product_code, component.guid)
        if state != 3:
            raise ProvenanceConflict()
        if component.keypath in files:
            expected = install_root / files[component.keypath].path
            if Path(location) != expected:
                raise ProvenanceConflict()
    for feature in features:
        if native.feature(package.product_code, feature) != 3:
            raise ProvenanceConflict()
