"""Writeback barrier for the exact locally installed ALT payload."""
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from uuid import UUID

from pc_agent.platform.linux.installation_lifecycle import InstallationPending
from tools.release.linux_native_verifier import MAX_PAYLOAD, run


MARKER = 'native-durability-reboot.json'
SELECTOR = Path('/opt/endpoint-agent/current.json')


def _boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if str(UUID(value)) != value:
        raise InstallationPending('native_durability_boot_unproved')
    return value


def _existing(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _private(path, uid, gid):
    from pc_agent.platform.linux.installation_notification import read_secret
    before = path.lstat()
    value = read_secret(path, uid=uid, gid=gid)
    try:
        acl = os.getxattr(path, 'system.posix_acl_access', follow_symlinks=False)
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise
        acl = b''
    # st_dev can change across boots, including for Btrfs subvolumes.
    mounts = json.loads(run(['/usr/bin/findmnt', '--json', '--target', str(path),
                              '--output', 'UUID,FSROOT'], timeout=5))['filesystems']
    if len(mounts) != 1 or not mounts[0].get('uuid') or not mounts[0].get('fsroot'):
        raise InstallationPending('native_durability_identity_filesystem_unproved')
    filesystem = mounts[0]['uuid'], mounts[0]['fsroot']
    after = path.lstat()
    attrs = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, attr) != getattr(after, attr) for attr in attrs):
        raise InstallationPending('native_durability_identity_changed')
    return [*filesystem, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
            hashlib.sha256(value).hexdigest(), hashlib.sha256(acl).hexdigest()]


def _package_path(value):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or not value or '\x00' in value:
        raise InstallationPending('native_durability_invalid_path')
    return path


def _sync_filesystems(paths):
    devices = {}
    for path in paths:
        # A symlink entry changes metadata on its parent's filesystem.
        info = path.lstat()
        anchor = path.parent if stat.S_ISLNK(info.st_mode) else path
        devices.setdefault(anchor.stat().st_dev, anchor)
    run(['/usr/bin/sync', '--file-system', '--', *map(str, devices.values())], timeout=75)


def _flush_selector(source):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(SELECTOR, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0)
                or info.st_mode & 0o022 or info.st_nlink != 1 or not 0 < info.st_size <= 4096):
            raise InstallationPending('native_durability_selector_invalid')
        if json.loads(os.read(fd, 4097)) != {'schema_version': 1, 'version': source['version'],
                                               'source_revision': source['source_revision']}:
            raise InstallationPending('native_durability_selector_changed')
        os.fsync(fd)
        current = SELECTOR.lstat()
        if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns) != (
                info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns):
            raise InstallationPending('native_durability_selector_changed')
    finally:
        os.close(fd)
    fd = os.open(SELECTOR.parent, flags | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class NativeDurability:
    def __init__(self, store):
        self.store = store

    @staticmethod
    def boot_id():
        return _boot_id()

    def assert_owner(self, operation):
        execution = operation.get('execution')
        if not isinstance(execution, dict) or execution != self.store.json('executor.json', missing=True):
            raise InstallationPending('native_durability_executor_changed')

    @staticmethod
    def identity_proof(*, delivery=None):
        from pwd import getpwnam
        from pc_agent.platform.linux.installation_notification import CA, CONFIG, DATA, canonical_identity
        paths = [DATA / name for name in ('device-credential', 'enrollment-identity.json')]
        present = [_existing(path) for path in paths]
        if any(present) and not all(present) and delivery is None:
            raise InstallationPending('native_durability_partial_identity')
        identity = {}
        if any(present) and delivery is not None:
            from pc_agent.platform.linux.installation_notification import read_secret, serialize_enrollment_identity
            account = getpwnam('endpoint-agent')
            expected = (delivery.device_token.encode('ascii'), serialize_enrollment_identity(delivery.device_id))
            for path, exists, value in zip(paths, present, expected):
                if exists and read_secret(path, uid=account.pw_uid, gid=account.pw_gid) != value:
                    raise InstallationPending('canonical_identity_changed')
        elif all(present):
            account = getpwnam('endpoint-agent')
            if canonical_identity()[0] is None:
                raise InstallationPending('native_durability_identity_invalid')
            identity.update({path.name: _private(path, account.pw_uid, account.pw_gid) for path in paths})
        for path in (CONFIG, CA):
            if _existing(path):
                identity[path.name] = _private(path, 0, 0)
        return identity

    def completed_identity_matches(self, operation, expected):
        delivery = None
        if 'device-credential' not in expected and operation.get('identity_recovery_required'):
            from endpoint_contracts.enrollment import AgentEnrollmentDeliveryV1
            from pc_agent.platform.linux.installation_notification import LinuxPrivateEnrollmentStore
            private = LinuxPrivateEnrollmentStore(self.store.paths.private)
            with private.locked():
                pending = private.read()
                if (pending and pending.get('delivery')
                        and pending['request'].get('native') == operation['source']):
                    delivery = AgentEnrollmentDeliveryV1.model_validate(pending['delivery'])
        return self.identity_proof(delivery=delivery) == expected

    def flush(self, action, source):
        from pc_agent.platform.linux.installation_notification import CA, CONFIG, DATA
        packages = ['endpoint-agent']
        if source['user_sensor_nevra']:
            packages.append('endpoint-agent-user-sensor')
        records = run(['/usr/bin/rpm', '-ql', *packages], limit=1024 * 1024, timeout=30).decode().splitlines()
        if not records:
            raise InstallationPending('native_durability_payload_paths_missing')
        db = _package_path(run(['/usr/bin/rpm', '--eval', '%{_dbpath}']).decode().strip()).resolve(strict=True)
        if not db.is_dir():
            raise InstallationPending('native_durability_rpmdb_missing')
        paths = [db, SELECTOR, self.store.paths.private]
        paths += [_package_path(name) for name in records]
        paths += [path for path in (CONFIG, CA, DATA) if _existing(path)]
        _flush_selector(source)
        _sync_filesystems(paths)
        _flush_selector(source)

    def orderly_reboot_proved(self, operation, previous_boot):
        marker = self.store.json(MARKER, missing=True)
        if (not isinstance(marker, dict) or set(marker) != {'operation_id', 'attempt', 'boot'}
                or marker['operation_id'] != operation['id']
                or marker['attempt'] != operation['durability']['attempt']):
            return False
        try:
            marker_boot = str(UUID(marker['boot']))
        except (ValueError, TypeError, AttributeError):
            return False
        return marker_boot == marker['boot'] and self.boot_id() not in (marker_boot, previous_boot)

    def mark_orderly_reboot(self, operation):
        if (not operation or operation.get('settled') or operation.get('unmanaged')
                or type(operation.get('exit_code')) is not int or operation['exit_code'] != 0):
            return
        proof = operation.get('durability')
        if not proof or proof.get('complete') is not False or not proof.get('attempt'):
            return
        marker = {'operation_id': operation['id'], 'attempt': proof['attempt'], 'boot': self.boot_id()}
        self.store.write(MARKER, json.dumps(marker, separators=(',', ':')).encode())

    def assert_hook_owner(self, operation):
        self.assert_owner(operation)
        with os.fdopen(os.open(sys.executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as image:
            before = os.fstat(image.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_PAYLOAD:
                raise InstallationPending('native_durability_executor_changed')
            digest = hashlib.file_digest(image, 'sha256').hexdigest()
            after = os.fstat(image.fileno())
            stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if stamp(before) != stamp(after) or digest != operation['execution'].get('sha256'):
                raise InstallationPending('native_durability_executor_changed')
