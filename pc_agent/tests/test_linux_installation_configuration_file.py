"""Exercise secure configuration reader against its OS boundary, on every platform."""
from pathlib import PurePosixPath
import stat
from types import SimpleNamespace

import pytest

from pc_agent.platform.linux import installation_configuration as c
from pc_agent.platform.linux.installation_lifecycle import InstallationPending
from pc_agent.tests.test_linux_native_staging_configuration import DROPIN, STAGING


class Filesystem:
    O_RDONLY, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK = 0, 1, 2, 4
    def __init__(self):
        self.nodes = {}
        self.handles = {}
        self.positions = {}
        self.after_read = lambda: None
        for index, path in enumerate(reversed(PurePosixPath(DROPIN).parents)):
            self.nodes[str(path)] = self.info(index, stat.S_IFDIR | 0o755)
        self.nodes[DROPIN] = self.info(99, stat.S_IFREG | 0o644, size=len(STAGING))
        self.raw = STAGING
    @staticmethod
    def info(inode, mode, size=1):
        return dict(st_dev=1,st_ino=inode,st_mode=mode,st_uid=0,st_gid=0,
            st_nlink=1,st_size=size,st_mtime_ns=10,st_ctime_ns=11)
    def path(self,name,dir_fd=None):
        return str(PurePosixPath(name)) if dir_fd is None else str(PurePosixPath(self.handles[dir_fd])/name)
    def open(self,name,flags,dir_fd=None):
        path = self.path(name,dir_fd)
        node = self.nodes[path]
        if stat.S_ISLNK(node['st_mode']) or flags & self.O_DIRECTORY and not stat.S_ISDIR(node['st_mode']):
            raise OSError('unsafe')
        fd = max(self.handles,default=2)+1
        self.handles[fd] = path
        self.positions[fd] = 0
        return fd
    def close(self,fd):
        del self.handles[fd]
    def fstat(self,fd):
        return SimpleNamespace(**self.nodes[self.handles[fd]])
    def stat(self,name,dir_fd=None,follow_symlinks=False):
        assert not follow_symlinks
        return SimpleNamespace(**self.nodes[self.path(name,dir_fd)])
    def read(self,fd,size):
        position = self.positions[fd]
        raw = self.raw[position:position+size]
        self.positions[fd] += len(raw)
        self.after_read()
        return raw


def filesystem(monkeypatch):
    fs = Filesystem()
    monkeypatch.setattr(c,'os',fs)
    return fs


def test_pinned_configuration_retains_bytes_inode_and_safe_ancestors(monkeypatch):
    fs = filesystem(monkeypatch)
    proof = c.configuration_file(DROPIN)
    assert proof['bytes'].encode() == STAGING
    assert proof['identity'] == [1,99,stat.S_IFREG | 0o644,0,0,1,215,10,11]
    assert len(proof['ancestors']) == 5
    assert fs.handles == {}
    fs.nodes['/etc']['st_mtime_ns'] += 1
    assert c.configuration_file(DROPIN) == proof  # Unrelated children are irrelevant.


@pytest.mark.parametrize('node,change', [
    (DROPIN,{'st_uid':1000}),(DROPIN,{'st_gid':1000}),
    (DROPIN,{'st_mode':stat.S_IFREG | 0o666}),(DROPIN,{'st_mode':stat.S_IFLNK | 0o777}),
    (DROPIN,{'st_mode':stat.S_IFDIR | 0o755}),(DROPIN,{'st_nlink':2}),
    ('/etc',{'st_uid':1000}),('/etc',{'st_gid':1000}),
    ('/etc',{'st_mode':stat.S_IFDIR | 0o775}),('/etc',{'st_mode':stat.S_IFLNK | 0o777}),
    ('/',{'st_mode':stat.S_IFDIR | 0o1777}),
])
def test_unsafe_file_or_ancestor_cannot_authorize_native_configuration(monkeypatch,node,change):
    fs = filesystem(monkeypatch)
    fs.nodes[node].update(change)
    with pytest.raises(InstallationPending): c.configuration_file(DROPIN)
    assert fs.handles == {}


@pytest.mark.parametrize('node,key',[ (DROPIN,'st_ino'),(DROPIN,'st_mtime_ns'),(DROPIN,'st_ctime_ns'),
    ('/etc','st_ino'),('/etc','st_mode')])
def test_replaced_or_changed_node_during_read_fails_closed(monkeypatch,node,key):
    fs = filesystem(monkeypatch)
    def change():
        fs.nodes[node][key] += 1
    fs.after_read = change
    with pytest.raises(InstallationPending): c.configuration_file(DROPIN)
    assert fs.handles == {}

# Root runs these in an isolated source snapshot; no host units are read/changed.
import os
from pathlib import Path


@pytest.fixture
def posix_configuration(tmp_path,monkeypatch):
    if os.name != 'posix' or os.geteuid() != 0:
        pytest.skip('requires POSIX root for real descriptor/ownership validation')
    for name,raw in [(DROPIN,STAGING),('/usr/lib/systemd/system/endpoint-agent.service',b'[Service]\n')]:
        path = tmp_path/name.lstrip('/')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
    for path in tmp_path.rglob('*'):
        if path.is_dir(): path.chmod(0o755)
    real_open,real_stat = os.open,os.stat
    def rooted_open(path,flags,**kw):
        return real_open(tmp_path if path == '/' else path,flags,**kw)
    def rooted_stat(path,**kw):
        return real_stat(tmp_path if path == '/' else path,**kw)
    interface = SimpleNamespace(open=rooted_open,stat=rooted_stat,
        fstat=os.fstat,read=os.read,close=os.close,
        O_RDONLY=os.O_RDONLY,O_DIRECTORY=os.O_DIRECTORY,O_NOFOLLOW=os.O_NOFOLLOW,O_NONBLOCK=os.O_NONBLOCK)
    monkeypatch.setattr(c,'os',interface)
    return tmp_path


@pytest.mark.parametrize('change',['file-owner','file-group','file-mode','file-link','file-symlink',
    'parent-owner','parent-group','parent-mode','parent-symlink'])
def test_real_posix_reader_rejects_unsafe_nodes(posix_configuration,change):
    root = posix_configuration
    file = root/DROPIN.lstrip('/')
    if change == 'file-owner': os.chown(file,1000,0)
    if change == 'file-group': os.chown(file,0,1000)
    if change == 'file-mode': file.chmod(0o664)
    if change == 'file-link': os.link(file,root/'second-link')
    if change == 'file-symlink':
        file.rename(root/'target')
        file.symlink_to(root/'target')
    if change == 'parent-owner': os.chown(file.parent,1000,0)
    if change == 'parent-group': os.chown(file.parent,0,1000)
    if change == 'parent-mode': file.parent.chmod(0o775)
    if change == 'parent-symlink':
        file.parent.rename(root/'target-parent')
        file.parent.symlink_to(root/'target-parent',target_is_directory=True)
    with pytest.raises(InstallationPending): c.configuration_file(DROPIN)


@pytest.mark.parametrize('active',[True,False])
def test_real_posix_replaced_identical_staging_inode_blocks_preparing_recovery(posix_configuration,monkeypatch,active):
    from pc_agent.tests.test_linux_native_staging_configuration import native, source
    root = posix_configuration
    store,journal,backend,coordinator = native(monkeypatch,active=active)
    monkeypatch.setattr(backend,'_configuration_file',c.configuration_file)
    journal.begin('upgrade',source())
    backend.prepare('upgrade',source())
    file = root/DROPIN.lstrip('/')
    original = file.stat()
    replacement = file.with_name('replacement')
    replacement.write_bytes(STAGING)
    replacement.chmod(0o644)
    os.utime(replacement,ns=(original.st_atime_ns,original.st_mtime_ns))
    replacement.replace(file)
    assert file.read_bytes() == STAGING and file.stat().st_ino != original.st_ino
    prior = list(backend.commands)
    with pytest.raises(InstallationPending): coordinator.reconcile(device_id=None)
    assert backend.commands == prior and 'runtime-ready' not in store.data
    assert journal.state()['operation']['phase'] == 'preparing'
