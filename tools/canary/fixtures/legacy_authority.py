"""Fixture-only fixed-image authority. Never import from production composition.

The sole legacy mapping was independently extracted from canonical MSI81 and
corroborated against its compiled pc_agent.version literal and frozen source.
This code makes no installed-readiness attestation and writes no update state.
"""
from dataclasses import dataclass
import re

IMAGE = r"C:\Program Files\Endpoint Platform\Agent\endpoint-agent-service.exe"
HOST_SHA256 = "4de1f985ac72ac74e910e0deffd406e5145cf21cce150df702febb15ca9c150c"
HOST_SIZE = 10284332
SOURCE = "c05bb0a528527ed1544c88fb0b1570c64b32084d"
PRODUCT = "{5E140EED-6A05-4D9B-98C6-BCC178C6EC71}"
COMPONENT = "{A10A61A1-B511-4A07-9D37-C592515D217E}"
SERVICE_SID = "S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
TRUSTED_WRITERS = frozenset({"S-1-5-18", "S-1-5-32-544", TRUSTED_INSTALLER})


class Rejected(PermissionError):
    """Bounded public refusal; native error details must not enter runtime logs."""


@dataclass(frozen=True)
class Token:
    user: str
    service_sid: str
    logon_sid: str
    session: int
    authentication_id: int


@dataclass(frozen=True)
class Process:
    pid: int
    parent: int
    created: int
    image: str
    token: Token


@dataclass(frozen=True)
class Service:
    pid: int
    service_type: int
    start_type: int
    state: int
    image_path: str
    account: str
    sid_type: int


@dataclass(frozen=True)
class Image:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class Observation:
    service: Service
    processes: tuple[Process, ...]
    image: Image


@dataclass(frozen=True)
class Authority:
    version: str
    kind: str


def check_acl(owner, aces, *, directory: bool) -> None:
    """Prove an upper bound on effective writes, without impersonating anyone.

    Only ordinary allow/deny ACEs are supported. Denies can only reduce this
    bound: a write allow to an untrusted trustee is rejected even if denied by
    another ACE. This intentionally conservative policy avoids guessing group
    membership. Inherit-only ACEs do not grant rights on this object; each actual
    ancestor/leaf descriptor is separately checked, so inherited effective ACEs
    are still checked. An untrusted owner is rejected for implicit WRITE_DAC.

    Directory ADD_SUBDIRECTORY is harmless to existing held chain components
    (present on genuine81's drive root); DELETE_CHILD is not. Generic writes are
    conservatively rejected. Users RX and unprotected inherited DACLs are valid.
    """
    if owner not in TRUSTED_WRITERS or aces is None or len(aces) > 256:
        raise Rejected("image_acl")
    # DELETE, WRITE_DAC, WRITE_OWNER, generic WRITE/ALL, write attributes/EA,
    # file write/append or directory add-file/delete-child.
    dangerous = 0x000D0112 | 0x50000000 | (0x40 if directory else 0x4)
    for kind, flags, mask, sid in aces:
        if kind not in {0, 1} or flags & ~0x1F or not sid:
            raise Rejected("image_acl")
        if kind == 0 and not flags & 8 and sid not in TRUSTED_WRITERS and mask & dangerous:
            raise Rejected("image_acl")


def _validate(value: Observation) -> None:
    s = value.service
    if (s.pid <= 0 or s.service_type != 0x10 or s.start_type != 2 or s.state != 4
        or s.image_path != f'"{IMAGE}" --agent-service'
        or s.account != r"NT AUTHORITY\LocalService" or s.sid_type != 1):
        raise Rejected("service_identity")
    chain = value.processes
    if len(chain) != 3:
        raise Rejected("service_ancestry")
    runtime, inner, outer = chain
    if (len({p.pid for p in chain}) != 3 or any(p.pid <= 0 for p in chain)
        or runtime.parent != inner.pid or inner.pid != s.pid or inner.parent != outer.pid
        or not 0 < outer.created < inner.created < runtime.created
        or runtime.image not in {
            rf"C:\Program Files\Endpoint Platform\Agent\versions\3.2.{n}\pc_agent.exe"
            for n in (83, 86, 87)
        }
        or any(p.image != IMAGE for p in (inner, outer))):
        raise Rejected("service_ancestry")
    identity = runtime.token
    if (identity.user != "S-1-5-19" or identity.service_sid != SERVICE_SID
        or not re.fullmatch(r"S-1-5-5-[0-9]+-[0-9]+", identity.logon_sid)
        or identity.session != 0 or identity.authentication_id <= 0
        or any(p.token != identity for p in chain)):
        raise Rejected("service_token")
    if (value.image.path != IMAGE or value.image.size <= 0
        or re.fullmatch(r"[0-9a-f]{64}", value.image.sha256) is None):
        raise Rejected("fixed_image")


def resolve(explicit: str | None, adapter=None) -> Authority:
    """Resolve before runtime startup; adapters are injectable solely for tests."""
    if explicit is not None and (not isinstance(explicit, str) or len(explicit) > 32
        or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", explicit)):
        raise Rejected("explicit_authority")
    if adapter is None:
        from tools.canary.fixtures.legacy_native import NativeAuthority
        adapter = NativeAuthority()
    try:
        with adapter.hold() as held:
            first = held.observe()
            _validate(first)
            if first.image.sha256 == HOST_SHA256:
                if first.image.size != HOST_SIZE or explicit not in {None, "3.2.81"}:
                    raise Rejected("legacy_conflict")
                held.require_legacy_product()
                result = Authority("3.2.81", "verified_legacy_fixed_image")
            else:
                # The ordinary fixed host supplies authority explicitly. Unknown
                # images NEVER acquire legacy authority, even by explicit81.
                if explicit is None or tuple(map(int, explicit.split("."))) < (3, 2, 82):
                    raise Rejected("missing_fixed_host_authority")
                result = Authority(explicit, "explicit_fixed_host")
            if held.recheck() != first:
                raise Rejected("changed_native_identity")
            return result
    except Rejected:
        raise
    except Exception:
        raise Rejected("native_observation_unavailable") from None
