"""Security boundaries of the isolated fixture entry; no native readiness claims."""
from contextlib import contextmanager
from dataclasses import replace
import importlib
from pathlib import Path

import pytest


def test_immutable_legacy_resolution_is_implemented():
    assert importlib.util.find_spec("tools.canary.fixtures.legacy_authority") is not None


@pytest.fixture
def authority():
    # A missing implementation is an explicit RED assertion, not a collection error.
    assert importlib.util.find_spec("tools.canary.fixtures.legacy_authority") is not None
    return importlib.import_module("tools.canary.fixtures.legacy_authority")


def observed(a):
    identity = a.Token("S-1-5-19", a.SERVICE_SID, "S-1-5-5-0-127227", 0, 987)
    return a.Observation(
        a.Service(20, 0x10, 2, 4, '"' + a.IMAGE + '" --agent-service', "NT AUTHORITY\\LocalService", 1),
        (a.Process(30, 20, 300, r"C:\Program Files\Endpoint Platform\Agent\versions\3.2.83\pc_agent.exe", identity),
         a.Process(20, 10, 200, a.IMAGE, identity),
         a.Process(10, 1, 100, a.IMAGE, identity)),
        a.Image(a.IMAGE, a.HOST_SHA256, 10284332),
    )


class Adapter:
    def __init__(self, first, second=None, product=True, error=None):
        self.first, self.second = first, second or first
        self.product, self.error, self.closed = product, error, False

    @contextmanager
    def hold(self):
        try:
            if self.error:
                raise self.error
            yield self
        finally:
            self.closed = True

    def observe(self):
        return self.first

    def recheck(self):
        return self.second

    def require_legacy_product(self):
        if not self.product:
            raise PermissionError("component unavailable")


def test_exact81_not_fixture_core_is_authority(authority):
    a = authority
    for explicit in (None, "3.2.81"):
        adapter = Adapter(observed(a))
        result = a.resolve(explicit, adapter)
        assert (result.version, result.kind) == ("3.2.81", "verified_legacy_fixed_image")
        assert adapter.closed


@pytest.mark.parametrize("explicit", ["", "3.2", "03.2.81", " 3.2.81", "0.0.0", "3.2.82"])
def test_exact81_cannot_be_overridden_by_argument(authority, explicit):
    with pytest.raises(authority.Rejected):
        authority.resolve(explicit, Adapter(observed(authority)))


def test_new_host_requires_explicit_ordinary_authority(authority):
    a = authority
    value = replace(observed(a), image=a.Image(a.IMAGE, "a" * 64, 123))
    assert a.resolve("3.2.82", Adapter(value)).version == "3.2.82"
    for explicit in (None, "3.2.81"):
        with pytest.raises(a.Rejected):
            a.resolve(explicit, Adapter(value))


@pytest.mark.parametrize("field,value", [("pid", 0), ("service_type", 0x110), ("start_type", 3),
    ("state", 2), ("image_path", "cmd.exe"), ("account", "LocalSystem"), ("sid_type", 0)])
def test_foreign_service_rejected(authority, field, value):
    a = authority
    obs = observed(a)
    with pytest.raises(a.Rejected):
        a.resolve(None, Adapter(replace(obs, service=replace(obs.service, **{field: value}))))


@pytest.mark.parametrize("index,field,value", [(0, "parent", 10), (1, "image", "cmd.exe"),
    (0, "image", "python.exe"),
    (2, "image", "python.exe"), (1, "created", 400), (2, "created", 200), (1, "pid", 30)])
def test_manual_intermediate_or_reused_process_rejected(authority, index, field, value):
    a = authority
    obs = observed(a)
    processes = list(obs.processes)
    processes[index] = replace(processes[index], **{field: value})
    with pytest.raises(a.Rejected):
        a.resolve(None, Adapter(replace(obs, processes=tuple(processes))))


@pytest.mark.parametrize("field,value", [("user", "S-1-5-18"), ("service_sid", ""),
    ("logon_sid", ""), ("session", 1), ("authentication_id", 988)])
def test_service_token_and_same_logon_required(authority, field, value):
    a = authority
    obs = observed(a)
    processes = list(obs.processes)
    processes[1] = replace(processes[1], token=replace(processes[1].token, **{field: value}))
    with pytest.raises(a.Rejected):
        a.resolve(None, Adapter(replace(obs, processes=tuple(processes))))


@pytest.mark.parametrize("failure", ["hash", "size", "path", "product", "access", "recheck", "creation_recheck", "image_recheck", "chain"])
def test_fail_closed_and_close_handles(authority, failure):
    a = authority
    obs = observed(a)
    first, second = obs, obs
    if failure in {"hash", "size", "path"}:
        changes = {"hash": {"sha256": "b" * 64}, "size": {"size": 1}, "path": {"path": r"C:\other.exe"}}
        first = replace(obs, image=replace(obs.image, **changes[failure]))
    if failure == "recheck":
        second = replace(obs, service=replace(obs.service, pid=99))
    if failure == "creation_recheck":
        second = replace(obs, processes=(obs.processes[0], replace(obs.processes[1], created=201), obs.processes[2]))
    if failure == "image_recheck":
        second = replace(obs, image=replace(obs.image, sha256="c" * 64))
    if failure == "chain":
        first = replace(obs, processes=obs.processes[:2])
    adapter = Adapter(first, second, product=failure != "product", error=OSError() if failure == "access" else None)
    with pytest.raises(a.Rejected):
        a.resolve(None, adapter)
    assert adapter.closed


def test_acl_allows_measured_rx_and_inherit_only_root_grants(authority):
    a = authority
    a.check_acl("S-1-5-18", [(0, 16, 0x1f01ff, "S-1-5-18"),
        (0, 16, 0x1200a9, "S-1-5-32-545")], directory=False)
    a.check_acl(a.TRUSTED_INSTALLER, [(0, 0, 4, "S-1-5-11"),
        (0, 8 | 3, 0x1301bf, "S-1-5-11")], directory=True)


@pytest.mark.parametrize("owner,aces,directory", [
    ("S-1-5-19", [], False), ("S-1-5-18", None, False),
    ("S-1-5-18", [(0, 0, 2, "S-1-5-32-545")], False),
    ("S-1-5-18", [(0, 16, 0x40, "S-1-5-11")], True),
    ("S-1-5-18", [(0, 0, 0x40000, "S-1-3-4")], True),
    ("S-1-5-18", [(0, 0, 0x80000, "S-1-5-19")], False),
    ("S-1-5-18", [(0, 0, 0x10000000, "S-1-5-11")], True),
    ("S-1-5-18", [(9, 0, 0, "S-1-5-11")], True),
])
def test_unsafe_acl_rejected(authority, owner, aces, directory):
    with pytest.raises(authority.Rejected):
        authority.check_acl(owner, aces, directory=directory)


def test_production_entry_spec_have_no_fixture_imports():
    root = Path(__file__).resolve().parents[2]
    for path in (root / "pc_agent/runtime/main.py", root / "pc_agent/pyinstaller_endpoint_core_windows.spec"):
        assert "tools.canary.fixtures" not in path.read_text(encoding="utf-8")


def test_native_adapter_is_available_and_refuses_nonservice_process():
    assert importlib.util.find_spec("tools.canary.fixtures.legacy_native") is not None
    from tools.canary.fixtures.legacy_authority import Rejected, resolve
    # This workstation invocation is intentionally not an installed service test.
    with pytest.raises(Rejected):
        resolve(None)
