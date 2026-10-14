"""Exact legacy metadata checks; these comparisons do not grant MSI authority.

Only reviewed79/81 can use successor major upgrade without modern old callbacks.
Native/cache admission, prepared retention and replaced-product verification are
separate required boundaries; a matching release alone does not close them.
"""
from dataclasses import dataclass
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


def inspect_foundation(paths,*,native=None):
    """Read exact historical foundation independently of the selected ZIP.

    This is read-only admission evidence, not retention or native completion.
    No modern foundation marker or legacy callback receipt is manufactured.
    """
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
    return release


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
