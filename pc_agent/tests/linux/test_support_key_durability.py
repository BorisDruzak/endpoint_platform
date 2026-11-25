import errno
import os
from pathlib import Path
import stat
import sys
import tempfile

import pytest

from pc_agent.platform.linux import support_access_service as service
from pc_agent.platform.linux.support_access import SupportError
from pc_agent.platform.linux.support_access_native import SupportPaths


pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or os.geteuid() != 0,
    reason='requires the root-owned Linux Support store',
)
KEY_FILES = {'host_ed25519', 'host_ed25519.pub', 'tunnel_ed25519', 'tunnel_ed25519.pub'}
DEVICE_ID = 'e46fc348-c48c-415c-a86a-1dd60ef14e1a'


@pytest.fixture
def registration(monkeypatch):
    requests = []
    credential_reads = []

    class Gateway:
        def __init__(self, origin, ca_path):
            pass

        def request(self, action, credential, body):
            requests.append((action, body))
            return dict(device_id=DEVICE_ID,
                        credential_id='e46fc348-c48c-415c-a86a-1dd60ef14e1b',
                        support_token='eps1.'+'x'*64), None

    def credential_reader():
        credential_reads.append(True)
        return 'device-credential'

    monkeypatch.setattr(service, 'SupportHTTPS', Gateway)
    with tempfile.TemporaryDirectory(dir='/var/tmp', prefix='support-key-test-') as root:
        paths = SupportPaths(Path(root)/'private', Path(root)/'public')

        def install(*, retained=False):
            return service.install_from_enrollment(
                device_id=DEVICE_ID, credential_reader=credential_reader,
                endpoint_origin='https://endpoint.sosnadmin.local',
                ca_bytes=b'ca', paths=paths, register_retained=retained,
            )

        yield paths, install, requests, credential_reads


def key_writeback(monkeypatch, private, *, fail_at=None):
    """Observe actual synced inodes and directory commits; inject a one-shot EIO."""
    fsync, replace = os.fsync, os.replace
    synced_files = set()
    synced_keys = set()
    pending = set()

    def sync(fd):
        nonlocal fail_at
        info = os.fstat(fd)
        inode = (info.st_dev, info.st_ino)
        path = Path(os.readlink(f'/proc/self/fd/{fd}'))
        if path == private and pending and fail_at == 'directory':
            fail_at = None
            pending.clear()
            raise OSError(errno.EIO, 'injected writeback failure')
        if stat.S_ISREG(info.st_mode) and path.parent == private:
            # The initial CA write is also synced but is not a key checkpoint.
            if fail_at == 'file' and (private/'tunnel_ed25519.pub').exists():
                fail_at = None
                raise OSError(errno.EIO, 'injected writeback failure')
            fsync(fd)
            synced_files.add(inode)
        else:
            fsync(fd)
        if path == private:
            synced_keys.update(pending)
            pending.clear()

    def publish(source, target):
        if target.parent == private and target.name in KEY_FILES:
            info = source.stat()
            inode = (info.st_dev, info.st_ino)
            if inode in synced_files:
                pending.add(target.name)
                synced_files.remove(inode)
        replace(source, target)

    monkeypatch.setattr(os, 'fsync', sync)
    monkeypatch.setattr(os, 'replace', publish)
    return synced_keys


def test_registration_waits_for_both_durable_key_pairs(monkeypatch, registration):
    paths, install, requests, credential_reads = registration
    synced_keys = key_writeback(monkeypatch, paths.private)
    original = service.SupportHTTPS.request

    def request(client, action, credential, body):
        assert synced_keys == KEY_FILES
        return original(client, action, credential, body)

    monkeypatch.setattr(service.SupportHTTPS, 'request', request)
    assert install()['installed']
    first = {name: (paths.private/name).read_bytes() for name in KEY_FILES}
    synced_keys.clear()

    assert install()['installed']
    assert not synced_keys
    assert len(requests) == len(credential_reads) == 1

    assert install(retained=True)['installed']
    assert requests[0] == requests[1]
    assert len(credential_reads) == 2
    assert {name: (paths.private/name).read_bytes() for name in KEY_FILES} == first


@pytest.mark.parametrize('fail_at', ['file', 'directory'])
def test_key_writeback_error_rewrites_same_pairs_before_retry(monkeypatch, registration, fail_at):
    paths, install, requests, credential_reads = registration
    synced_keys = key_writeback(monkeypatch, paths.private, fail_at=fail_at)
    with pytest.raises(SupportError):
        install()
    assert not requests
    assert not credential_reads
    first = {name: (paths.private/name).read_bytes() for name in KEY_FILES}
    assert all(first.values())
    synced_keys.clear()

    assert install()['installed']
    assert synced_keys == KEY_FILES
    assert len(requests) == len(credential_reads) == 1
    assert {name: (paths.private/name).read_bytes() for name in KEY_FILES} == first


def test_retained_registered_identity_with_corrupt_key_is_preserved(registration):
    paths, install, requests, credential_reads = registration
    assert install()['installed']
    corrupt = paths.private/'tunnel_ed25519'
    corrupt.write_bytes(b'')
    config = (paths.private/'config.json').read_bytes()

    with pytest.raises(SupportError):
        install(retained=True)
    assert corrupt.read_bytes() == b''
    assert (paths.private/'config.json').read_bytes() == config
    assert len(requests) == len(credential_reads) == 1


def test_parent_writeback_error_blocks_registration_until_store_is_created_again(
    monkeypatch, registration,
):
    paths, install, requests, credential_reads = registration
    fsync = os.fsync
    parent_syncs = []

    def sync(fd):
        if Path(os.readlink(f'/proc/self/fd/{fd}')) == paths.private.parent:
            parent_syncs.append(not any(paths.private.iterdir()))
            if len(parent_syncs) == 1:
                raise OSError(errno.EIO, 'injected parent writeback failure')
        fsync(fd)

    monkeypatch.setattr(os, 'fsync', sync)
    with pytest.raises(SupportError):
        install()
    assert not requests
    assert not credential_reads
    assert not paths.private.exists()

    assert install()['installed']
    assert parent_syncs[:2] == [True, True]
    assert len(requests) == len(credential_reads) == 1


def test_existing_empty_store_is_synced_to_parent_before_registration(monkeypatch, registration):
    paths, install, requests, _ = registration
    paths.private.mkdir(mode=0o700)
    fsync = os.fsync
    parent_synced = []

    def sync(fd):
        if Path(os.readlink(f'/proc/self/fd/{fd}')) == paths.private.parent:
            parent_synced.append(not any(paths.private.iterdir()))
        fsync(fd)

    monkeypatch.setattr(os, 'fsync', sync)
    assert install()['installed']
    assert parent_synced[0]
    assert len(requests) == 1


def test_registration_syncs_nonempty_retained_store_without_replacing_identity(
    monkeypatch, registration,
):
    paths, install, requests, credential_reads = registration
    assert install()['installed']
    before = {name: (paths.private/name).read_bytes() for name in KEY_FILES}
    fsync = os.fsync
    parent_syncs = []

    def sync(fd):
        if Path(os.readlink(f'/proc/self/fd/{fd}')) == paths.private.parent:
            parent_syncs.append(True)
            if len(parent_syncs) == 1:
                raise OSError(errno.EIO, 'injected retained parent writeback failure')
        fsync(fd)

    monkeypatch.setattr(os, 'fsync', sync)
    assert install()['installed']
    assert not parent_syncs

    with pytest.raises(SupportError):
        install(retained=True)
    assert len(requests) == len(credential_reads) == 1
    assert {name: (paths.private/name).read_bytes() for name in KEY_FILES} == before

    assert install(retained=True)['installed']
    assert len(parent_syncs) == 2
    assert requests[0] == requests[1]
    assert len(credential_reads) == 2
    assert {name: (paths.private/name).read_bytes() for name in KEY_FILES} == before
