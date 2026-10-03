"""Setup and fixed-host read-only MSI package and installed ownership adapter.

Opening the database never opens an installation session or runs MSI actions.
The offline worker must not import this module.
"""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
import os
import re

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
from pathlib import Path
import uuid

from endpoint_contracts.runtime_payload import PayloadConflict, PayloadIdentity, reject_reparse_ancestors, safe_path, version_tuple

ProvenanceConflict = PayloadConflict
UPGRADE_CODE = "{D4F3045C-51CF-49D9-AF9C-3AEBF206ED1F}"
FOUNDATION_FEATURE = "EndpointAgentFeature"
RUNTIME_FEATURE = "EndpointAgentInitialRuntimeFeature"
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_ROWS = 10000


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
    import msilib
    try:
        reject_reparse_ancestors(path)
        before = path.stat()
        if before.st_nlink != 1 or not 0 < before.st_size <= MAX_PACKAGE_BYTES:
            raise ProvenanceConflict()
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
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
        output = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(output))
        result = self._api('MsiGetProductInfoW', [wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)])(code, name, output, ctypes.byref(length))
        if result or not output.value:
            raise ProvenanceConflict()
        return output.value

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
    if name not in {'EndpointInstallerHost', 'EndpointInitialRuntimeInventory'} or not 0 < maximum <= MAX_PACKAGE_BYTES:
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
    files = {item.name: item for item in package.files}
    for component in components:
        if any(native.feature(package.product_code, feature) != 3 for feature in component.features):
            raise ProvenanceConflict()
        state, location = native.component(package.product_code, component.guid)
        if state != 3:
            raise ProvenanceConflict()
        if component.keypath in files:
            expected = install_root / files[component.keypath].path
            if Path(location) != expected:
                raise ProvenanceConflict()
