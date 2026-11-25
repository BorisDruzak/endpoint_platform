"""Retry the optional Observer removal of one completed standalone uninstall."""

from uuid import UUID

from endpoint_contracts.runtime_payload import read_json
from . import durable_state, installation_lifecycle, installation_provenance, installer_fence, msi_inventory, native_setup_observer
from .compound_upgrade_plan import _validate_completed, has_active_upgrade


def _authority(paths, transaction, release, package):
    from .installer_transaction_bridge import _settled

    _settled(paths)
    if installer_fence.read_fence(paths) is not None or has_active_upgrade(paths):
        raise ValueError('UPDATE_IN_PROGRESS')
    if not isinstance(transaction, str) or str(UUID(transaction)) != transaction:
        raise ValueError('OWNER_AUTH_FAILED')
    history = installer_fence.state_root(paths) / 'transactions'
    installer_fence.assert_state_security(history)
    archive = history / transaction
    installer_fence.assert_state_security(archive)
    completed = read_json(installation_provenance._read(archive / 'completed.json', 16384), 16384)
    _validate_completed(completed, release, transaction, 'uninstall')
    if completed['package']['package_code'] != package.package_code or not completed['helpers']:
        raise ValueError('PROVENANCE_CONFLICT')

    cleanup = read_json(installation_provenance._read(archive / 'observer-cleanup.json', 4096), 4096)
    if (not isinstance(cleanup, dict) or set(cleanup) != {'schema_version', 'transaction_id', 'package_sha256',
            'native_result', 'native_uninstalled', 'observer_cleanup'}
            or type(cleanup['schema_version']) is not int or cleanup['schema_version'] != 1
            or cleanup['transaction_id'] != transaction or cleanup['package_sha256'] != release['package_sha256']
            or type(cleanup['native_result']) is not int or cleanup['native_result'] != 0
            or cleanup['native_uninstalled'] is not True or cleanup['observer_cleanup'] not in {'removed', 'incomplete'}):
        raise ValueError('PROVENANCE_CONFLICT')

    # A normal final uninstall records its native fact before the Observer
    # receipt. Journal append order is independent of clocks and delivery.
    loaded = installation_lifecycle.outbox_for(paths)._load()
    facts = loaded[1]['facts'] if loaded is not None else []
    if not facts:
        raise ValueError('PROVENANCE_CONFLICT')
    latest = facts[-1]
    if (latest['transaction_id'] != transaction or latest['action'] != 'removed'
            or latest['native'] != {'version': release['version'], 'product_code': release['product_code'],
                                    'source_revision': release['source_revision'],
                                    'msi_sha256': release['package_sha256'], 'exit_code': 0}):
        raise ValueError('PROVENANCE_CONFLICT')
    support_status = latest['cleanup']['support']
    support_receipt = archive / 'support-cleanup.json'
    if support_status != 'not_applicable' or installation_provenance._present(support_receipt):
        recorded = read_json(installation_provenance._read(support_receipt, 4096), 4096)
        if (not isinstance(recorded, dict) or type(recorded.get('schema_version')) is not int
                or type(recorded.get('native_result')) is not int
                or recorded.get('native_uninstalled') is not True
                or support_status not in {'complete', 'incomplete'}
                or recorded != {'schema_version': 1, 'transaction_id': transaction,
                                'package_sha256': release['package_sha256'], 'native_result': 0,
                                'native_uninstalled': True, 'support_cleanup': support_status}):
            raise ValueError('PROVENANCE_CONFLICT')
    return archive, cleanup['observer_cleanup'], support_status


def retry_observer_cleanup(paths, transaction, release, expected):
    """Run only within the authenticated cleanup phase of the installer owner."""
    archive, prior, support_status = _authority(paths, transaction, release, expected.package)
    native = msi_inventory.NativeMsi()
    msi_inventory.verify_uninstalled(expected.package, paths.install_root, native=native)
    if native.related_products(msi_inventory.UPGRADE_CODE):
        raise ValueError('PROVENANCE_CONFLICT')
    if getattr(expected, 'foundation_schema', 1) == 3:
        # Check current absence against the exact protected package. The original
        # Support receipt and lifecycle fact remain immutable.
        try:
            msi_inventory.verify_support_uninstalled(expected, paths.install_root, native=native)
        except ValueError as error:
            if str(error) != 'SUPPORT_CLEANUP_INCOMPLETE':
                raise
            support_status = 'incomplete'
        else:
            support_status = 'complete'
    elif support_status != 'not_applicable':
        raise ValueError('PROVENANCE_CONFLICT')

    if prior == 'removed':
        outcome = 'removed' if _observer_task_is_absent() else 'incomplete'
    else:
        durable_state.installer_mutation_checkpoint(required=True)
        outcome = native_setup_observer.retire_packaged_observer(paths)
        native_setup_observer.write_observer_cleanup_receipt(archive, transaction, release['package_sha256'], outcome)
    return {'observer_cleanup': outcome, 'support_cleanup': support_status}


def _observer_task_is_absent():
    try:
        folder = native_setup_observer._scheduler_folder()
        return native_setup_observer.find_task(folder, native_setup_observer._TASK_NAME) is None
    except Exception:
        return False
