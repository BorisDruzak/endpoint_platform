"""Offline durable exclusion from a surviving Windows Installer transaction.

Public fence data is readable by fixed service identities, writable only by
SYSTEM/Administrators. It is separate from service-writable OTA journals.
No idle/PID/age predicate or ordinary update caller may retire this evidence.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import uuid

from endpoint_contracts.runtime_payload import read_json, reject_reparse_ancestors, version_tuple
from .durable_state import write_json_atomic
from .update_paths import WindowsUpdatePaths

PHASES = ("prepared", "msi-starting", "msi-executing", "msi-returned", "reconciling", "complete")
MAX_FENCE_BYTES = 16 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")
_SOURCE = re.compile(r"^[0-9a-f]{40}$")
_ADMINS = {"S-1-5-18", "S-1-5-32-544"}
_FIELDS = {"schema_version", "transaction_id", "phase", "operation", "package",
    "selected", "previous", "service_states", "service_startup", "startup_restored", "sequence", "helpers"}


class InstallerFenceActive(RuntimeError):
    def __init__(self):
        super().__init__("INSTALLER_RECOVERY_REQUIRED")


def state_root(paths: WindowsUpdatePaths) -> Path:
    # Sibling of Agent under protected Program Files, never inside the writable
    # ProgramData Agent tree whose parent could delete a protected child.
    return paths.install_root.parent / "installer-state"


def _guid(value):
    if not isinstance(value, str):
        raise ValueError("UPDATE_STATE_INVALID")
    if value != "{" + str(uuid.UUID(value)).upper() + "}":
        raise ValueError("UPDATE_STATE_INVALID")


def validate_fence(payload):
    try:
        if (not isinstance(payload, dict) or set(payload) != _FIELDS
            or type(payload["schema_version"]) is not int or payload["schema_version"] != 1
            or payload["phase"] not in PHASES
            or payload["operation"] not in {"install", "retire-initial-runtime", "uninstall"}
            or str(uuid.UUID(payload["transaction_id"])) != payload["transaction_id"]
            or type(payload["sequence"]) is not int or not 0 <= payload["sequence"] <= 256):
            raise ValueError()
        package = payload["package"]
        if (not isinstance(package, dict) or set(package) != {
            "sha256", "product_code", "package_code", "version", "source_revision"}
            or not isinstance(package["sha256"], str) or not _HASH.fullmatch(package["sha256"])
            or not isinstance(package["source_revision"], str) or not _SOURCE.fullmatch(package["source_revision"])):
            raise ValueError()
        version_tuple(package["version"])
        _guid(package["product_code"])
        _guid(package["package_code"])
        for key in ("selected", "previous"):
            if payload[key] is not None and (not isinstance(payload[key], str) or not _HASH.fullmatch(payload[key])):
                raise ValueError()
        states = payload["service_states"]
        if (not isinstance(states, dict) or set(states) != {"EndpointAgent", "EndpointAgentUpdater"}
            or any(value not in {"absent", "running", "stopped"} for value in states.values())):
            raise ValueError()
        helpers = payload["helpers"]
        startup = payload["service_startup"]
        if (not isinstance(startup, dict) or set(startup) != set(states)
            or type(payload["startup_restored"]) is not bool):
            raise ValueError()
        for value in startup.values():
            if value is not None and (not isinstance(value, dict) or set(value) != {"start_type", "delayed_auto"}
                or type(value["start_type"]) is not int or value["start_type"] not in {2,3,4}
                or type(value["delayed_auto"]) is not bool):
                raise ValueError()
        if not isinstance(helpers, list) or len(helpers) > 64:
            raise ValueError()
        for helper in helpers:
            if (not isinstance(helper, dict) or set(helper) != {"pid", "creation_time", "image_sha256", "phase", "complete"}
                or type(helper["pid"]) is not int or helper["pid"] <= 0
                or type(helper["creation_time"]) is not int or helper["creation_time"] <= 0
                or not isinstance(helper["image_sha256"], str) or not _HASH.fullmatch(helper["image_sha256"])
                or helper["phase"] not in PHASES or type(helper["complete"]) is not bool):
                raise ValueError()
        return payload
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise ValueError("UPDATE_STATE_INVALID") from error


def assert_state_security(path: Path, *, secret: bool = False) -> None:
    reject_reparse_ancestors(path)
    if os.name != "nt":
        details = path.stat()
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError("UPDATE_STATE_INVALID")
        return
    import win32security
    from .update_transaction import _SERVICE_SIDS
    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    dacl, owner = descriptor.GetSecurityDescriptorDacl(), descriptor.GetSecurityDescriptorOwner()
    if (owner is None or win32security.ConvertSidToStringSid(owner) not in _ADMINS
        or dacl is None or not descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED):
        raise ValueError("UPDATE_STATE_INVALID")
    seen = set()
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        if len(ace) != 3 or ace[0][0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise ValueError("UPDATE_STATE_INVALID")
        sid = win32security.ConvertSidToStringSid(ace[2])
        seen.add(sid)
        if sid not in _ADMINS:
            if secret or sid not in _SERVICE_SIDS or ace[1] & ~0x1200A9:
                raise ValueError("UPDATE_STATE_INVALID")
    if not _ADMINS <= seen or (not secret and not set(_SERVICE_SIDS) <= seen):
        raise ValueError("UPDATE_STATE_INVALID")
    # A protected leaf DACL does not prevent a parent DELETE_CHILD grant.
    # Validate the effective containing-directory deletion/ACL authority too.
    trusted_parents = _ADMINS | {'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}
    for parent in path.parents:
        security = win32security.GetNamedSecurityInfo(str(parent), win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        owner = security.GetSecurityDescriptorOwner()
        acl = security.GetSecurityDescriptorDacl()
        if owner is None or win32security.ConvertSidToStringSid(owner) not in trusted_parents or acl is None:
            raise ValueError('UPDATE_STATE_INVALID')
        for index in range(acl.GetAceCount()):
            ace = acl.GetAce(index)
            if len(ace) != 3 or ace[0][0] != win32security.ACCESS_ALLOWED_ACE_TYPE:
                raise ValueError('UPDATE_STATE_INVALID')
            if ace[0][1] & win32security.INHERIT_ONLY_ACE:
                continue
            if win32security.ConvertSidToStringSid(ace[2]) not in trusted_parents and ace[1] & 0x500D0040:
                raise ValueError('UPDATE_STATE_INVALID')


def protect_state(path: Path, *, secret: bool = False) -> None:
    from .durable_state import installer_mutation_checkpoint
    installer_mutation_checkpoint()
    if os.name != "nt":
        path.chmod(0o700 if path.is_dir() else 0o600)
        return
    import win32security
    from .update_transaction import _SERVICE_SIDS
    inheritance = "OICI" if path.is_dir() else ""
    sddl = "O:BAG:BAD:P" + "".join(f"(A;{inheritance};FA;;;{sid})" for sid in sorted(_ADMINS))
    if not secret:
        sddl += "".join(f"(A;{inheritance};0x1200a9;;;{sid})" for sid in _SERVICE_SIDS)
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        descriptor.GetSecurityDescriptorOwner(), None, descriptor.GetSecurityDescriptorDacl(), None)
    assert_state_security(path, secret=secret)


def read_fence(paths: WindowsUpdatePaths):
    root = state_root(paths)
    try:
        root.lstat()
    except FileNotFoundError:
        return None
    try:
        assert_state_security(root)
        path = root / "transaction.json"
        try:
            details = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ValueError("UPDATE_STATE_INVALID")
        assert_state_security(path)
        with path.open("rb") as source:
            return validate_fence(read_json(source.read(MAX_FENCE_BYTES + 1), MAX_FENCE_BYTES))
    except (OSError, ValueError) as error:
        raise ValueError("UPDATE_STATE_INVALID") from error


def assert_launch_allowed(paths: WindowsUpdatePaths) -> None:
    if read_fence(paths) is not None:
        raise ValueError("INSTALLER_RECOVERY_REQUIRED")


def publish_fence(paths: WindowsUpdatePaths, payload: dict) -> None:
    """Installer-owned phase only; caller proves its live bridge capability."""
    validate_fence(payload)
    root = state_root(paths)
    assert_state_security(root)
    previous = read_fence(paths)
    if previous is not None:
        if (previous["transaction_id"] != payload["transaction_id"] or previous["package"] != payload["package"]
            or previous["operation"] != payload["operation"]
            or previous["selected"] != payload["selected"] or previous["previous"] != payload["previous"]
            or previous["service_states"] != payload["service_states"]
            or previous["service_startup"] != payload["service_startup"]
            or (previous["startup_restored"] and not payload["startup_restored"])
            or payload["sequence"] < previous["sequence"]
            or PHASES.index(payload["phase"]) < PHASES.index(previous["phase"])):
            raise ValueError("UPDATE_STATE_INVALID")
    write_json_atomic(root / "transaction.json", payload, trusted_root=root,
        max_bytes=MAX_FENCE_BYTES, protect=protect_state)
