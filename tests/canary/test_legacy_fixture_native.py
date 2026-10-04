"""Exercise native adapters at OS-call boundaries, never installed acceptance."""
import os
from types import SimpleNamespace

import pytest

from tools.canary.fixtures.legacy_authority import IMAGE, Rejected, SERVICE_SID
from tools.canary.fixtures.legacy_native import NativeAuthority
from contextlib import nullcontext


@pytest.mark.skipif(os.name != "nt", reason="read-only Windows process API characterization")
def test_real_held_current_process_can_be_queried_without_elevation():
    adapter = NativeAuthority()
    with adapter.hold():
        current = adapter._open_process(os.getpid())
        assert current.pid == os.getpid()
        assert current.created > 0
        assert current.parent > 0
        assert adapter._process(*adapter.processes[0]) == current
    # Passing here proves these APIs for our test runner, not LocalService.


class Descriptor:
    def __init__(self, owner="S-1-5-18", aces=(((0, 16), 0x1200a9, "S-1-5-32-545"),)):
        self.owner, self.aces = owner, aces

    def GetSecurityDescriptorOwner(self):
        return self.owner

    def GetSecurityDescriptorDacl(self):
        return self if self.aces is not None else None

    def GetAceCount(self):
        return len(self.aces)

    def GetAce(self, index):
        return self.aces[index]


def file_adapter(*, attrs=0x20, path="\\\\?\\" + IMAGE, links=1, descriptor=None):
    native = NativeAuthority()
    descriptor = descriptor or Descriptor()
    native.file = SimpleNamespace(
        GetFileInformationByHandle=lambda handle: (attrs, 1, 2, 3, 42, 0, 10, links, 0, 987),
        GetFinalPathNameByHandle=lambda handle, flags: path,
    )
    native.security = SimpleNamespace(
        GetSecurityInfo=lambda handle, kind, requested: descriptor,
        ConvertSidToStringSid=lambda sid: sid,
    )
    return native


def test_native_descriptor_preserves_inherited_users_rx():
    assert file_adapter()._file_identity(1, IMAGE, False)


@pytest.mark.parametrize("changes", [
    {"attrs": 0x420}, {"attrs": 0x10}, {"path": r"\\?\C:\other.exe"}, {"links": 2},
    {"descriptor": Descriptor(owner="S-1-5-19")}, {"descriptor": Descriptor(aces=None)},
    {"descriptor": Descriptor(aces=(((0, 16), 0x40000, SERVICE_SID),))},
    {"descriptor": Descriptor(aces=(((5, 0), 0, "object", "inherited", "SID"),))},
])
def test_native_file_checks_reject_unsafe_objects(changes):
    with pytest.raises(Rejected):
        file_adapter(**changes)._file_identity(1, IMAGE, False)


class Call:
    def __init__(self, fn):
        self.fn = fn

    def __call__(self, *args):
        return self.fn(*args)


@pytest.mark.parametrize("failure", [None, "product", "version", "component", "keypath", "length", "access"])
def test_machine_msi_inventory_is_exact_and_fail_closed(monkeypatch, failure):
    from tools.canary.fixtures import legacy_native as native
    def product(code, user, context, prop, buffer, length):
        assert code == "{5E140EED-6A05-4D9B-98C6-BCC178C6EC71}"
        assert user is None and context == 4
        buffer.value = "5" if prop == "State" else "3.2.81"
        if failure == "product" and prop == "State":
            buffer.value = "1"
        if failure == "version" and prop == "VersionString":
            buffer.value = "3.2.82"
        length._obj.value = 9999 if failure == "length" else len(buffer.value)
        return 5 if failure == "access" else 0
    def state(code, user, context, component, result):
        assert code == "{5E140EED-6A05-4D9B-98C6-BCC178C6EC71}"
        assert component == "{A10A61A1-B511-4A07-9D37-C592515D217E}"
        assert user is None and context == 4
        result._obj.value = 2 if failure == "component" else 3
        return 0
    def path(code, component, user, context, buffer, length):
        assert code == "{5E140EED-6A05-4D9B-98C6-BCC178C6EC71}"
        assert component == "{A10A61A1-B511-4A07-9D37-C592515D217E}"
        assert user is None and context == 4
        buffer.value = "C:\\other.exe" if failure == "keypath" else IMAGE
        length._obj.value = len(buffer.value)
        return 3
    dll = SimpleNamespace(MsiGetProductInfoExW=Call(product), MsiQueryComponentStateW=Call(state), MsiGetComponentPathExW=Call(path))
    monkeypatch.setattr(native.ctypes, "WinDLL", lambda name, **kw: dll, raising=False)
    if failure is None:
        NativeAuthority().require_legacy_product()
    else:
        with pytest.raises(Rejected):
            NativeAuthority().require_legacy_product()


def test_native_hash_detects_file_growing_during_read():
    native = file_adapter()
    native.files = [(IMAGE, False, 1, None)]
    native.file.SetFilePointer = lambda *args: None
    native.file.ReadFile = lambda *args: (0, b"x" * 11)
    with pytest.raises(Rejected, match="image_changed"):
        native._hash_image()


def test_image_identity_swap_on_recheck_is_rejected():
    native = file_adapter()
    native.files = [(IMAGE, False, 1, ("different file ID",))]
    native._assert_not_impersonating = lambda: None
    with pytest.raises(Rejected, match="image_identity_changed"):
        native.recheck()


class Handle:
    def __init__(self):
        self.closed = False

    def Close(self):
        assert not self.closed
        self.closed = True


@pytest.mark.parametrize("service_flags,restricted,error", [(14, False, False), (16, False, False),
    (0, False, False), (14, True, False), (14, False, True)])
def test_token_query_is_minimal_enabled_only_and_always_closed(service_flags, restricted, error):
    native = NativeAuthority()
    handle = Handle()
    values = {
        "TokenGroups": [(SERVICE_SID, service_flags), ("S-1-5-5-0-42", 0xC0000004)],
        "TokenRestrictedSids": [("SID", 4)] if restricted else [], "TokenType": 1,
        "TokenUser": ("S-1-5-19", 0), "TokenSessionId": 0,
        "TokenStatistics": {"AuthenticationId": 42},
    }
    def opened(process, access):
        assert access == 8  # no READ_CONTROL, duplication or privilege adjustment
        return handle
    def query(token, kind):
        if error:
            raise OSError("denied token query")
        return values[kind]
    native.security = SimpleNamespace(**{key: key for key in values},
        OpenProcessToken=opened, GetTokenInformation=query, ConvertSidToStringSid=lambda sid: sid)
    if restricted or error:
        with pytest.raises((Rejected, OSError)):
            native._token(123)
    else:
        observed = native._token(123)
        assert observed.service_sid == (SERVICE_SID if service_flags == 14 else "")
        assert observed.authentication_id == 42
    assert handle.closed


@pytest.mark.skipif(os.name != "nt", reason="native resource-scope initialization")
@pytest.mark.parametrize("fail_at", [1, 2, 3, 4, 5, None])
def test_all_opened_chain_handles_close_on_every_exit(monkeypatch, fail_at):
    native = NativeAuthority()
    handles, paths = [], []
    def opened(path, access, share, attributes, creation, flags, template):
        paths.append(path)
        directory = len(paths) < 5
        assert access == (0x20080 if directory else 0x80000000)
        assert share == (3 if directory else 1)  # no SHARE_DELETE; file has no SHARE_WRITE
        assert flags & 0x00200000  # OPEN_REPARSE_POINT
        if len(paths) == fail_at:
            raise OSError("denied open")
        handle = Handle()
        handles.append(handle)
        return handle
    with pytest.raises(OSError) if fail_at is not None else nullcontext():
        with native.hold():
            native.file = SimpleNamespace(CreateFile=opened)
            monkeypatch.setattr(native, "_file_identity", lambda *args: ("checked",))
            monkeypatch.setattr(native, "_hash_image", lambda: "checked")
            assert native._open_image_chain() == "checked"
    assert all(handle.closed for handle in handles)
    if fail_at is None:
        assert paths == ["C:\\", "C:\\Program Files", "C:\\Program Files\\Endpoint Platform",
            "C:\\Program Files\\Endpoint Platform\\Agent", IMAGE]


@pytest.mark.parametrize("failure", ["denied", "pid_reused", "exited", "times_denied"])
def test_native_process_query_rejects_inconsistent_or_exited_handle(failure):
    import ctypes
    native = NativeAuthority()
    def basic(handle, kind, value, size, count):
        value._obj.pid = 99 if failure == "pid_reused" else 10
        count._obj.value = ctypes.sizeof(value._obj)
        return -1 if failure == "denied" else 0
    def times(handle, created, exited, kernel, user):
        created._obj.low = 100
        exited._obj.low = 123 if failure == "exited" else 0
        return failure != "times_denied"
    native._basic, native._times = basic, times
    native._token = lambda handle: pytest.fail("token query after invalid process")
    with pytest.raises(Rejected):
        native._process(10, 123)
