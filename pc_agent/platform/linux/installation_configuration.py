"""Read native configuration through pinned root-owned directory descriptors."""
import os
from pathlib import PurePosixPath
import stat

from pc_agent.platform.linux.installation_lifecycle import InstallationPending

STAGING_DROPIN = '/etc/systemd/system/endpoint-agent.service.d/staging.conf'
STAGING_ENVIRONMENT = {
    'ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT': 'staging',
    'CANARY_ENVIRONMENT': 'staging',
    'CANARY_APPROVED': 'true',
    'ENDPOINT_AGENT_ORIGIN': 'https://endpoint-staging.sosnadmin.local',
}
STAGING_BYTES = ('[Service]\n' + ''.join(
    f'Environment={name}={value}\n' for name, value in STAGING_ENVIRONMENT.items()))


def _directory_identity(info):
    # Unrelated children may change directory times, size and link count.
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def _file_identity(info):
    return _directory_identity(info) + [info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns]


def configuration_file(path):
    """Bind bytes, security and inode; never follow a symlink at any depth."""
    parts = PurePosixPath(path).parts
    if not parts or parts[0] != '/' or any(part in ('.', '..') for part in parts):
        raise InstallationPending('unsafe_native_configuration_path')
    descriptors, ancestors = [], []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        for component in parts[1:-1]:
            info = os.fstat(parent)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_mode & 0o022):
                raise InstallationPending('unsafe_native_configuration_parent')
            ancestors.append(_directory_identity(info))
            parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(parent)
        info = os.fstat(parent)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o022):
            raise InstallationPending('unsafe_native_configuration_parent')
        ancestors.append(_directory_identity(info))
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
            or before.st_mode & 0o022 or before.st_nlink != 1 or not 0 < before.st_size <= 65536):
            raise InstallationPending('unsafe_native_configuration_file')
        raw = bytearray()
        while chunk := os.read(fd, min(4096, 65537 - len(raw))):
            raw.extend(chunk)
            if len(raw) > 65536:
                raise InstallationPending('native_configuration_bound')
        # Check both retained handles and their names (including ancestors).
        if (_file_identity(os.fstat(fd)) != _file_identity(before)
            or _file_identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) != _file_identity(before)
            or len(raw) != before.st_size):
            raise InstallationPending('native_configuration_changed')
        for index, directory in enumerate(descriptors[:-1]):
            named = os.stat('/', follow_symlinks=False) if index == 0 else os.stat(
                parts[index], dir_fd=descriptors[index-1], follow_symlinks=False)
            if (_directory_identity(os.fstat(directory)) != ancestors[index]
                or _directory_identity(named) != ancestors[index]):
                raise InstallationPending('native_configuration_parent_changed')
        return {'identity': _file_identity(before), 'ancestors': ancestors,
            'bytes': raw.decode('utf-8')}
    except (OSError, UnicodeError):
        raise InstallationPending('unsafe_native_configuration_file') from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
