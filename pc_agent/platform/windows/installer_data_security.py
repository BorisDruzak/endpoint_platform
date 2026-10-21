"""Protected pre-native evidence for preserving enrollment security descriptors.

Only the authenticated installer helper calls these operations. No credential
contents or credential digests are read, written or returned by this module.
"""
import os
import hashlib
import json
import re
import stat
import uuid

from endpoint_contracts.runtime_payload import read_json
from . import acl, durable_state
from .installer_fence import state_root

_LEAVES = ("device-credential", "enrollment-identity.json", "endpoint-ca.crt", "endpoint-origin")
_MAX_BYTES = 32768


def assert_state_security(path, **kwargs):
    from . import installer_fence
    installer_fence.assert_state_security(path, **kwargs)


def protect_state(path, **kwargs):
    from . import installer_fence
    installer_fence.protect_state(path, **kwargs)


def _root(paths):
    return paths.pending_path.parents[1]


def _transaction_root(paths, request):
    return state_root(paths) / "transactions" / request["transaction_id"]


def _prepare_transaction_root(paths, request):
    from .installation_provenance import _archive_directory
    root = _transaction_root(paths, request)
    _archive_directory(_archive_directory(root.parent.parent, root.parent.name), root.name)
    return root


def _snapshot(paths):
    root = _root(paths)
    for ancestor in reversed((root, *root.parents)):
        try:
            ancestor.lstat()
        except FileNotFoundError:
            continue
        acl._assert_nonreparse_directory(ancestor)
    if os.name == "nt":
        security, rights = acl.PyWin32AclAdapter._modules()
        acl._assert_machine_data_parent_authority(root, security)
    try:
        initial = root.lstat()
    except FileNotFoundError:
        return {"root": None, "leaves": {}}
    if os.name != "nt":
        raise ValueError("native enrollment security inspection requires Windows")
    security, rights = acl.PyWin32AclAdapter._modules()
    validated_root_descriptor = acl._validate_existing_machine_data_acl(root, security, rights)

    def snapshot(path, directory=False, validated_descriptor=None):
        try:
            details = path.lstat()
        except FileNotFoundError:
            return None
        if (path.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(details.st_mode))
            or (not directory and details.st_nlink != 1)):
            raise ValueError("PROVENANCE_CONFLICT")
        descriptor = validated_descriptor if validated_descriptor is not None else security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.GROUP_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
        if security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in {"S-1-5-18", "S-1-5-32-544"}:
            raise ValueError("PROVENANCE_CONFLICT")
        if not directory:
            acl._validate_machine_data_leaf_acl(path.name, descriptor, security, rights)
        encoded = bytes(descriptor)
        if len(encoded) > 4096:
            raise ValueError("PROVENANCE_CONFLICT")
        final = path.lstat()
        if ((final.st_dev, final.st_ino) != (details.st_dev, details.st_ino)
            or (not directory and final.st_nlink != 1)
            or getattr(final, "st_file_attributes", 0) & 0x400):
            raise ValueError("PROVENANCE_CONFLICT")
        return {"identity": [details.st_dev, details.st_ino], "descriptor": encoded.hex()}

    root_snapshot = snapshot(root, True, validated_root_descriptor)
    if root_snapshot["identity"] != [initial.st_dev, initial.st_ino]:
        raise ValueError("PROVENANCE_CONFLICT")
    return {"root": root_snapshot, "leaves": {name: snapshot(root / name) for name in _LEAVES}}


def _binding(request):
    transaction, session = request["transaction_id"], request["session_id"]
    package = request["release"]["package_sha256"]
    if (str(uuid.UUID(transaction)) != transaction or str(uuid.UUID(session)) != session
        or not isinstance(package, str) or not re.fullmatch("[0-9a-f]{64}", package)):
        raise ValueError("PROVENANCE_CONFLICT")
    return {"transaction_id": transaction, "package_sha256": package, "session_id": session}


def _validate_snapshot(snapshot):
    if not isinstance(snapshot, dict) or set(snapshot) != {"root", "leaves"} or not isinstance(snapshot["leaves"], dict):
        raise ValueError("PROVENANCE_CONFLICT")
    if snapshot["root"] is None:
        if snapshot["leaves"]:
            raise ValueError("PROVENANCE_CONFLICT")
        return
    if set(snapshot["leaves"]) != set(_LEAVES):
        raise ValueError("PROVENANCE_CONFLICT")
    for item in (snapshot["root"], *snapshot["leaves"].values()):
        if item is None:
            continue
        if (not isinstance(item, dict) or set(item) != {"identity", "descriptor"}
            or not isinstance(item["identity"], list) or len(item["identity"]) != 2
            or any(type(value) is not int or value < 0 for value in item["identity"])
            or not isinstance(item["descriptor"], str) or not 0 < len(item["descriptor"]) <= 8192
            or len(item["descriptor"]) % 2 or not re.fullmatch("[0-9a-f]+", item["descriptor"])):
            raise ValueError("PROVENANCE_CONFLICT")


def _read(paths, request):
    path = _transaction_root(paths, request) / "data-root-before.json"
    assert_state_security(path, secret=True)
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > _MAX_BYTES:
        raise ValueError("PROVENANCE_CONFLICT")
    with path.open("rb") as stream:
        record = read_json(stream.read(_MAX_BYTES + 1), _MAX_BYTES)
    if (not isinstance(record, dict) or set(record) != {"schema_version", "binding", "snapshot", "phase"}
        or type(record["schema_version"]) is not int or record["schema_version"] != 1
        or record["phase"] not in {"prepared", "native-entered", "configured"}
        or not isinstance(record["snapshot"], dict) or set(record["snapshot"]) != {"root", "leaves"}):
        raise ValueError("PROVENANCE_CONFLICT")
    binding = _binding(request)
    original = record["binding"]
    if (not isinstance(original, dict) or set(original) != set(binding)
        or any(original[key] != binding[key] for key in ("transaction_id", "package_sha256"))
        ):
        raise ValueError("PROVENANCE_CONFLICT")
    if not isinstance(original["session_id"], str) or str(uuid.UUID(original["session_id"])) != original["session_id"]:
        raise ValueError("PROVENANCE_CONFLICT")
    _validate_snapshot(record["snapshot"])
    if original['session_id'] != binding['session_id'] and request.get('recovery') is not True:
        try:
            handoff = _handoff_path(paths, request)
            assert_state_security(handoff, secret=True)
            details = handoff.lstat()
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size > _MAX_BYTES:
                raise ValueError('PROVENANCE_CONFLICT')
            receipt = read_json(handoff.read_bytes(), _MAX_BYTES)
            if receipt != {'source': original, 'target': binding, 'capture_sha256': _capture_hash(record)}:
                raise ValueError('PROVENANCE_CONFLICT')
        except OSError as error:
            raise ValueError('PROVENANCE_CONFLICT') from error
    return record


def _write(paths, request, record):
    root = _transaction_root(paths, request)
    durable_state.write_json_atomic(root / "data-root-before.json", record, trusted_root=root,
        max_bytes=_MAX_BYTES, protect=lambda path: protect_state(path, secret=True))


def prepare(paths, request):
    record = {"schema_version": 1, "binding": _binding(request), "snapshot": _snapshot(paths), "phase": "prepared"}
    _validate_snapshot(record["snapshot"])
    _prepare_transaction_root(paths, request)
    path = _transaction_root(paths, request) / "data-root-before.json"
    if path.exists():
        existing = _read(paths, request)
        if existing['phase'] != 'prepared' or existing['snapshot'] != record['snapshot']:
            raise ValueError("PROVENANCE_CONFLICT")
        return
    _write(paths, request, record)


def _capture_hash(record):
    return hashlib.sha256(json.dumps({'binding': record['binding'], 'snapshot': record['snapshot']},
        sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def _handoff_path(paths, request):
    binding = _binding(request)
    return _transaction_root(paths, request) / ('session-handoff-' + binding['session_id'] + '.json')


def prepared_source_session(paths, request):
    # Recovery reads validate the original proof, but grant no mutation authority.
    record = _read(paths, {**request, 'recovery': True})
    if record['phase'] != 'prepared':
        raise ValueError('PROVENANCE_CONFLICT')
    return record['binding']['session_id']


def adopt_prepared_session(paths, source_request, target_request):
    from .staged_update_state import read_staged_update
    durable_state.installer_mutation_checkpoint(required=True)
    staged = read_staged_update(paths)
    source, target = _binding(source_request), _binding(target_request)
    if (staged is None or staged.phase != 'switching' or staged.binding.operation_id != target['transaction_id']
            or source['session_id'] == target['session_id']
            or any(source[key] != target[key] for key in ('transaction_id', 'package_sha256'))):
        raise ValueError('PROVENANCE_CONFLICT')
    record = _read(paths, source_request)
    if record['phase'] != 'prepared' or record['snapshot'] != _snapshot(paths):
        raise ValueError('PROVENANCE_CONFLICT')
    receipt = {'source': source, 'target': target, 'capture_sha256': _capture_hash(record)}
    path = _handoff_path(paths, target_request)
    if path.exists():
        _read(paths, target_request)
        return
    durable_state.write_json_atomic(path, receipt, trusted_root=path.parent,
        max_bytes=_MAX_BYTES, protect=lambda leaf: protect_state(leaf, secret=True))


def before_native(paths, request):
    record = _read(paths, request)
    if request.get("recovery") is True:
        if record["snapshot"]["root"] is not None:
            if _snapshot(paths) != record["snapshot"]:
                raise ValueError("PROVENANCE_CONFLICT")
        else:
            root = _root(paths)
            try:
                root.lstat()
            except FileNotFoundError:
                if _snapshot(paths)!={'root':None,'leaves':{}}:
                    raise ValueError('PROVENANCE_CONFLICT')
                return
            if record["phase"] == "prepared":
                raise ValueError("PROVENANCE_CONFLICT")
            if record["phase"] == "configured":
                _snapshot(paths)
            else:
                _assert_fresh_native_root(paths)
        return
    if record["phase"] != "prepared" or _snapshot(paths) != record["snapshot"]:
        raise ValueError("PROVENANCE_CONFLICT")


def enter_native(paths, request):
    before_native(paths, request)
    record = _read(paths, request)
    record["phase"] = "native-entered"
    _write(paths, request, record)


def _assert_fresh_native_root(paths):
    security, rights = acl.PyWin32AclAdapter._modules()
    root = _root(paths)
    acl._assert_nonreparse_directory(root)
    acl._assert_trusted_owner(root, security)
    acl._assert_machine_data_parent_authority(root, security)
    if any(root.iterdir()):
        # This is only a postcondition of authenticated pre-native absence,
        # never a general permission to normalize arbitrary empty directories.
        raise ValueError("PROVENANCE_CONFLICT")
    return security, rights


def _initialize_fresh_root(paths):
    security, rights = _assert_fresh_native_root(paths)
    root = _root(paths)
    acl.replace_machine_data_acl(root, win32security=security, ntsecuritycon=rights, trusted_root=root.parent.parent)


def configure(paths, request):
    record = _read(paths, request)
    if record["phase"] != "native-entered":
        raise ValueError("PROVENANCE_CONFLICT")
    if record["snapshot"]["root"] is None:
        _initialize_fresh_root(paths)
    elif _snapshot(paths) != record["snapshot"]:
        raise ValueError("PROVENANCE_CONFLICT")
    record["phase"] = "configured"
    _write(paths, request, record)


def verify_preserved(paths, request):
    record = _read(paths, request)
    if record["phase"] != "configured":
        raise ValueError("PROVENANCE_CONFLICT")
    if record["snapshot"]["root"] is not None and _snapshot(paths) != record["snapshot"]:
        raise ValueError("PROVENANCE_CONFLICT")
    if record["snapshot"]["root"] is None and record["phase"] == "configured":
        snapshot = _snapshot(paths)
        if snapshot["root"] is None or any(value is not None for value in snapshot["leaves"].values()):
            raise ValueError("PROVENANCE_CONFLICT")
