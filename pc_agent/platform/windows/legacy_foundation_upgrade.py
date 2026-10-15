"""Exact legacy metadata checks; these comparisons do not grant MSI authority.

Only reviewed79/81 can use successor major upgrade without modern old callbacks.
Native/cache admission, prepared retention and replaced-product verification are
separate required boundaries; a matching release alone does not close them.
"""
from dataclasses import dataclass
from contextlib import contextmanager,ExitStack
import os
import re
import stat
import uuid
from pathlib import Path
from .msi_inventory import NativeMsi,PackageInventory,ProvenanceConflict,guid
from .runtime_identity import _LEGACY_MSI_CONTRACTS

UPGRADE_CODE='{D4F3045C-51CF-49D9-AF9C-3AEBF206ED1F}'
_PRODUCTS={
 '2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a':'{0FFBDA26-8617-4F9E-A378-833F01048360}',
 'ad4dc49703513d6dee6fd3e51ac94a09c5967112d58aed4e60a63cf6966251f5':'{5E140EED-6A05-4D9B-98C6-BCC178C6EC71}',
}
# Read from filServiceHost in cab1.cab of the exact original79 MSI above.
# This identifies its shared Agent/Updater host, not a reconstructed release.
_SHARED79_PACKAGE='2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a'
_SHARED79_HOST_SIZE=34094212
_SHARED79_HOST_SHA256='6100c2351bd65827b4c16b1f7fb77a0007ca9ca192bc512f1642797e62182b11'


def canonical_release(value):
    if not isinstance(value,dict):raise ProvenanceConflict()
    digest=value.get('package_sha256')
    if not isinstance(digest,str) or digest not in _PRODUCTS:return None
    contract=_LEGACY_MSI_CONTRACTS[digest]
    expected={'schema_version':'endpoint_windows_release_v1','version':contract['version'],
        'source_revision':contract['source_revision'],'package_sha256':digest,
        'initial_runtime_tree_sha256':contract['tree_sha256'],'product_code':_PRODUCTS[digest]}
    if value!=expected:raise ProvenanceConflict()
    return expected


def verify_registration(package,release,*,native=None):
    release=canonical_release(release)
    if release is None or any(getattr(package,field)!=release[key] for field,key in
        (('sha256','package_sha256'),('version','version'),('product_code','product_code'))):
        raise ProvenanceConflict()
    native=native or NativeMsi();code=package.product_code
    if (native.product(code)!=5 or native.property(code,'AssignmentType')!='1'
        or native.property(code,'PackageCode')!=package.package_code
        or native.property(code,'VersionString')!=package.version
        or native.product_metadata(code,'Transforms')!='' or native.has_patches(code)
        or native.related_products(UPGRADE_CODE)!=(code,)):
        raise ProvenanceConflict()


def _runtime_release(package):
    contract=_LEGACY_MSI_CONTRACTS.get(package.sha256)
    if (contract is None or package.version!=contract['version']
        or package.product_code!=_PRODUCTS[package.sha256]):
        raise ProvenanceConflict()
    return canonical_release({'schema_version':'endpoint_windows_release_v1',
        'version':contract['version'],'source_revision':contract['source_revision'],
        'package_sha256':package.sha256,'initial_runtime_tree_sha256':contract['tree_sha256'],
        'product_code':package.product_code})


def assert_runtime_security(paths,package):
    """Servicing-only ACLs for exact historical runtime; no execution authority.

    Callers separately prove either the live native owner or its authenticated
    retained archive and native absence. Selectors/journals remain strict.
    """
    from endpoint_contracts.runtime_payload import reject_reparse_ancestors
    from . import msi_inventory
    from .installer_fence import assert_namespace_security
    _runtime_release(package)
    root=paths.versions_root/package.version
    try:
        reject_reparse_ancestors(root);assert_namespace_security(root)
        msi_inventory._assert_registered_cache_security(root)
        if not root.is_dir():raise ProvenanceConflict()
        count=0
        for path in root.rglob('*'):
            count+=1
            if count>10000:raise ProvenanceConflict()
            reject_reparse_ancestors(path)
            details=path.lstat()
            if not stat.S_ISDIR(details.st_mode) and (not stat.S_ISREG(details.st_mode) or details.st_nlink!=1):
                raise ProvenanceConflict()
            msi_inventory._assert_registered_cache_security(path)
        assert_namespace_security(root)
    except (OSError,ValueError) as error:
        raise ProvenanceConflict() from error


def read_runtime_marker(paths,package):
    """Bounded pinned read, only for an actually registered canonical79/81 MSI."""
    release=_runtime_release(package)
    verify_registration(package,release)
    data=_read_runtime_marker_file(paths,package)
    verify_registration(package,release)
    return data


def _read_runtime_marker_file(paths,package):
    """Archive-restoration callers separately require verified archive/absence."""
    from . import durable_state
    from endpoint_contracts.runtime_payload import read_json
    _runtime_release(package)
    assert_runtime_security(paths,package)
    marker=paths.versions_root/package.version/'.endpoint-msi-runtime.json'
    try:
        before=durable_state._copy_identity(marker.lstat())
        if not 0<before[2]<=4096:raise ProvenanceConflict()
        with durable_state._pinned_copy_source(marker) as descriptor:
            opened=os.fstat(descriptor)
            if durable_state._copy_identity(opened)!=before:raise ProvenanceConflict()
            data=os.read(descriptor,4097)
            after=os.fstat(descriptor)
            if (len(data)!=before[2] or durable_state._copy_identity(after)!=before
                or after.st_ctime_ns!=opened.st_ctime_ns
                or durable_state._copy_identity(marker.lstat())!=before):raise ProvenanceConflict()
        contract=_LEGACY_MSI_CONTRACTS[package.sha256]
        if read_json(data,4096)!={'schema_version':1,'version':package.version,
            'component_guid':contract['component_guid']}:raise ProvenanceConflict()
        assert_runtime_security(paths,package)
        return data
    except (OSError,ValueError,TypeError,KeyError) as error:
        raise ProvenanceConflict() from error


def inspect_foundation(paths,*,native=None):
    """Read exact historical foundation independently of the selected ZIP.

    This is read-only admission evidence, not retention or native completion.
    No modern foundation marker or legacy callback receipt is manufactured.
    """
    role=_registered_foundation(paths,native=native)
    return role.release if role is not None else None


def _registered_foundation(paths,*,native=None):
    """Internal exact receipt/media/native/cache proof, never caller authority."""
    from endpoint_contracts.runtime_payload import read_json
    from . import installation_provenance as provenance,msi_inventory
    cache=paths.updates_root.parent/'installer-cache'
    receipt=cache/'installer-provenance.json'
    if not provenance._present(receipt):return None
    record=read_json(provenance._read(receipt,4096),4096)
    fields={'schema_version','release_manifest_schema_version','cache_file','version',
        'source_revision','package_sha256','initial_runtime_tree_sha256','product_code'}
    if set(record)!=fields or record['schema_version']!='endpoint_windows_installer_provenance_v1':
        raise ProvenanceConflict()
    release={key:record[key] for key in fields-{'schema_version','release_manifest_schema_version','cache_file'}}
    release['schema_version']=record['release_manifest_schema_version']
    release=canonical_release(release)
    if release is None or record['cache_file']!=f"msi-{release['package_sha256']}/EndpointAgent.msi":
        raise ProvenanceConflict()
    native=native or NativeMsi()
    if native.product(release['product_code'])==-1:
        _verify_inert_receipt(paths,release,native)
        return None
    original=cache/record['cache_file'];provenance._assert_security(original)
    package=msi_inventory.read_package(original,release['package_sha256'])
    verify_registration(package,release,native=native)
    msi_inventory.verify_foundation(package,paths.install_root,native=native)
    msi_inventory.verify_registered_cache(original,package,native=native)
    verify_registration(package,release,native=native)
    return LegacyPredecessor(release,package,original)


@dataclass(frozen=True)
class _PinnedSharedServiceHost:
    path: Path
    role: object
    native: object
    descriptor: int
    identity: tuple
    change_time: int

    def check(self):
        from . import durable_state,msi_inventory
        from .installer_fence import assert_namespace_security
        try:
            verify_registration(self.role.package,self.role.release,native=self.native)
            assert_namespace_security(self.path)
            msi_inventory._assert_registered_cache_security(self.path)
            opened=os.fstat(self.descriptor)
            if (durable_state._copy_identity(self.path.lstat())!=self.identity
                or durable_state._copy_identity(opened)!=self.identity
                or opened.st_ctime_ns!=self.change_time):raise ProvenanceConflict()
        except (OSError,ValueError) as error:
            raise ProvenanceConflict() from error


@contextmanager
def _verified_shared_service_host(paths):
    """Original79-only proof and deny-write/delete pin for one SCM context.

    Native MSI must start after this context exits. No proof is accepted from
    a caller, fleet snapshot, receipt boolean or service filename alone.
    """
    from . import durable_state
    native=NativeMsi()
    role=_registered_foundation(paths,native=native)
    if role is None or role.package.sha256!=_SHARED79_PACKAGE:
        raise ProvenanceConflict()
    path=paths.install_root/'endpoint-agent-service.exe'
    with ExitStack() as stack:
        try:
            before=durable_state._copy_identity(path.lstat())
            if before[2]!=_SHARED79_HOST_SIZE:raise ProvenanceConflict()
            descriptor=stack.enter_context(durable_state._pinned_copy_source(path))
            proof=_PinnedSharedServiceHost(path,role,native,descriptor,before,os.fstat(descriptor).st_ctime_ns)
            proof.check()
            durable_state._verify_copy_bytes(descriptor,_SHARED79_HOST_SIZE,_SHARED79_HOST_SHA256)
            proof.check()
        except (OSError,ValueError) as error:
            raise ProvenanceConflict() from error
        yield proof


def _verify_inert_receipt(paths,release,native):
    """Retain historical bytes after an existing protected uninstall proof.

    This only classifies an absent foundation. It creates no installation or
    recovery authority, and no timestamp or live-process inference is used.
    """
    from endpoint_contracts.runtime_payload import read_json,version_tuple
    from . import installation_provenance as provenance,msi_inventory
    from .installer_fence import state_root,assert_state_security,read_fence,validate_fence
    from .compound_upgrade_plan import has_active_upgrade

    def absent():
        if (has_active_upgrade(paths) or read_fence(paths) is not None
            or native.product(release['product_code'])!=-1
            or native.related_products(UPGRADE_CODE)!=()
            or provenance._present(paths.install_root)):
            raise ProvenanceConflict()

    absent()
    root=state_root(paths)/'transactions'
    assert_state_security(root)
    found=False
    # Historical transaction count is bounded before accumulating entries.
    # Every inspected namespace and proof retains the existing ACL/link checks.
    with os.scandir(root) as entries:
        for count,entry in enumerate(entries,1):
            if count>128:raise ProvenanceConflict()
            transaction=Path(entry.path)
            if (str(uuid.UUID(entry.name))!=entry.name
                or not stat.S_ISDIR(transaction.lstat().st_mode)):
                raise ProvenanceConflict()
            assert_state_security(transaction)
            proof=transaction/'completed.json'
            if not provenance._present(proof):continue
            assert_state_security(proof)
            completed=validate_fence(read_json(provenance._read(proof,16384),16384))
            if completed['transaction_id']!=entry.name:raise ProvenanceConflict()
            if (completed['operation']!='uninstall' or completed['phase']!='complete'
                or completed['startup_restored'] is not True):continue
            maintenance=transaction/'maintenance.json'
            assert_state_security(maintenance)
            record=read_json(provenance._read(maintenance,16384),16384)
            modern=record['release']
            # Only the exact release-bound original protected media is read;
            # no executable or MSI path from a receipt is ever followed.
            if (not isinstance(modern,dict) or not isinstance(modern.get('package_sha256'),str)
                or not re.fullmatch('[0-9a-f]{64}',modern['package_sha256'])):
                raise ProvenanceConflict()
            media=state_root(paths)/'packages'/modern['package_sha256']/'EndpointAgent.msi'
            assert_state_security(media.parent)
            assert_state_security(media)
            expected=msi_inventory.read_expected_package(media,modern)
            identity={key:getattr(expected.package,key) for key in
                ('sha256','product_code','package_code','version')}
            identity['source_revision']=modern['source_revision']
            if (completed['package']!=identity or expected.package.product_code==release['product_code']
                or version_tuple(expected.package.version)<=version_tuple(release['version'])):
                raise ProvenanceConflict()
            request={'package_path':media,'release':modern,'transaction_id':entry.name,
                'selected':completed['selected'],'previous':completed['previous']}
            provenance.validate_maintenance_recovery(paths,request,'uninstall')
            msi_inventory.verify_uninstalled(expected.package,paths.install_root,native=native)
            assert_state_security(proof)
            assert_state_security(maintenance)
            found=True
    if not found:raise ProvenanceConflict()
    absent()


@dataclass(frozen=True)
class LegacyPredecessor:
    release: dict
    package: PackageInventory
    media: Path


def prepared_predecessor(paths,request):
    """Derive the old role from the existing package/selection-bound plan."""
    from endpoint_contracts.runtime_payload import version_tuple
    from . import installation_provenance as provenance,msi_inventory
    from .installer_fence import state_root,assert_state_security
    from .runtime_identity import verify_retained_archive
    expected=provenance._expected_request(request)
    root=state_root(paths)/'provenance'/request['transaction_id']
    assert_state_security(root)
    plan=provenance._read_plan(root,request,expected)
    result=None
    for archive_id in plan['archives']:
        retained=verify_retained_archive(paths,archive_id)
        recorded=retained.record['package'];digest=recorded['sha256']
        if digest not in _PRODUCTS:continue
        if archive_id not in {request['selected'],request['previous']}:raise ProvenanceConflict()
        contract=_LEGACY_MSI_CONTRACTS[digest]
        release=canonical_release({'schema_version':'endpoint_windows_release_v1',
            'version':retained.identity.version,'source_revision':retained.identity.source_revision,
            'package_sha256':digest,'initial_runtime_tree_sha256':contract['tree_sha256'],
            'product_code':recorded['product_code']})
        media=retained.archive/'package.msi'
        package=msi_inventory.read_package(media,digest)
        if (result is not None or package.product_code==expected.package.product_code
            or version_tuple(package.version)>=version_tuple(expected.package.version)
            or any(getattr(package,key)!=recorded[key] for key in ('sha256','product_code','package_code','version'))
            or package.version!=release['version']):raise ProvenanceConflict()
        result=LegacyPredecessor(release,package,media)
    return result


def verify_prepared_foundation(paths,request,foundation):
    observed=canonical_release(foundation) if foundation is not None else None
    role=prepared_predecessor(paths,request)
    if (role.release if role is not None else None)!=observed:raise ProvenanceConflict()
    return role


def recovery_selector_options(paths,request):
    from . import installation_provenance as provenance,msi_inventory
    if prepared_predecessor(paths,request) is None:return {}
    expected=provenance._expected_request(request)
    return {'native_current':msi_inventory.read_native_selector(request['package_path'],expected),
        'allow_native_absence':True}


def verify_detected_targets(product_code,detected):
    product_code=guid(product_code)
    if not isinstance(detected,str) or len(detected)>4096:raise ProvenanceConflict()
    # FindRelatedProducts may append one terminal separator. No duplicate,
    # additional or empty interior item is accepted as an uninstall target.
    values=detected[:-1] if detected.endswith(';') else detected
    if not values or tuple(guid(item) for item in values.split(';'))!=(product_code,):
        raise ProvenanceConflict()


def verify_native_preflight(paths,request,detected,*,recovery=False,native=None):
    """Require actual MSI targets before the successor deferred script."""
    from . import installation_provenance as provenance,msi_inventory
    role=prepared_predecessor(paths,request)
    if role is None:
        if detected!='':raise ProvenanceConflict()
        return
    native=native or NativeMsi()
    expected=provenance._expected_request(request)
    new=expected.package;old_state=native.product(role.package.product_code)
    if old_state==5:
        if native.product(new.product_code)!=-1:raise ProvenanceConflict()
        verify_detected_targets(role.package.product_code,detected)
        verify_registration(role.package,role.release,native=native)
        msi_inventory.verify_foundation(role.package,paths.install_root,native=native)
        msi_inventory.verify_registered_cache(role.media,role.package,native=native)
        verify_registration(role.package,role.release,native=native)
    elif old_state==-1 and recovery is True:
        # This exact prepared transition already reached native successor
        # ownership. Repair uses the same successor; it cannot uninstall a
        # newly appeared third product or revive an old callback authority.
        if (detected!='' or native.product(new.product_code)!=5
            or native.property(new.product_code,'AssignmentType')!='1'
            or native.property(new.product_code,'PackageCode')!=new.package_code
            or native.property(new.product_code,'VersionString')!=new.version
            or native.product_metadata(new.product_code,'Transforms')!=''
            or native.has_patches(new.product_code)
            or native.related_products(UPGRADE_CODE)!=(new.product_code,)):
            raise ProvenanceConflict()
        msi_inventory.verify_registered_cache(request['package_path'],new,native=native)
    else:raise ProvenanceConflict()


def verify_completed_replacement(paths,request):
    """Old absence and exact new ownership precede completion/startup."""
    from . import installation_provenance as provenance,msi_inventory
    role=prepared_predecessor(paths,request)
    if role is not None:
        expected=provenance._expected_request(request)
        msi_inventory.verify_replaced_product(role.package,expected.package,paths.install_root)
