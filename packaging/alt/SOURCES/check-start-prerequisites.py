#!/usr/bin/python3
"""Validate the immutable install selection and service bootstrap inputs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
from uuid import RFC_4122, UUID


INSTALL_ROOT = Path("/opt/endpoint-agent")
DATA_ROOT = Path("/var/lib/endpoint-agent")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
DEVICE_CREDENTIAL = re.compile(rb"[A-Za-z0-9_-]{43}\Z")
IDENTITY_SCHEMA = "endpoint_enrollment_identity_v1"
RUNTIME_DIRECTORIES = (
    (Path("/etc/endpoint-agent"), "root", 0o755),
    (DATA_ROOT, "endpoint-agent", 0o750),
    (Path("/var/log/endpoint-agent"), "endpoint-agent", 0o750),
)


def _fail(message: str) -> None:
    print(f"endpoint-agent start prerequisite failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def _regular_file(path: Path, *, nonempty: bool = True) -> os.stat_result:
    try:
        details = os.lstat(path)
    except OSError:
        _fail(f"missing regular file: {path}")
    if not stat.S_ISREG(details.st_mode):
        _fail(f"unsafe non-regular file: {path}")
    if nonempty and details.st_size == 0:
        _fail(f"empty required file: {path}")
    return details


def _safe_root_program(path: Path, *, executable: bool = False) -> None:
    details = _regular_file(path)
    if details.st_uid != 0 or details.st_gid != 0:
        _fail(f"program file is not root-owned: {path}")
    if details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        _fail(f"program file is writable outside root: {path}")
    if executable and not details.st_mode & stat.S_IXUSR:
        _fail(f"program file is not executable: {path}")


def _prepare_runtime_directories() -> None:
    if os.geteuid() != 0:
        _fail("runtime directory preparation requires root")
    for path, owner_name, mode in RUNTIME_DIRECTORIES:
        parent = path.parent
        parent_details = os.lstat(parent)
        if (
            not stat.S_ISDIR(parent_details.st_mode)
            or parent_details.st_uid != 0
            or parent_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            _fail(f"unsafe runtime directory parent: {parent}")
        owner = pwd.getpwnam(owner_name)
        try:
            details = os.lstat(path)
        except FileNotFoundError:
            os.mkdir(path, mode)
            os.chown(path, owner.pw_uid, owner.pw_gid)
            os.chmod(path, mode)
            continue
        if not stat.S_ISDIR(details.st_mode) or details.st_mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            _fail(f"unsafe existing runtime directory: {path}")
        if details.st_uid == owner.pw_uid and details.st_gid == owner.pw_gid:
            if stat.S_IMODE(details.st_mode) != mode:
                _fail(f"unsafe existing runtime directory mode: {path}")
            continue
        if (
            details.st_uid == 0
            and details.st_gid == 0
            and stat.S_IMODE(details.st_mode) == 0o755
            and not any(path.iterdir())
        ):
            os.chown(path, owner.pw_uid, owner.pw_gid)
            os.chmod(path, mode)
            continue
        _fail(f"unsafe existing runtime directory ownership: {path}")


def _selected_release() -> str:
    launcher = INSTALL_ROOT / "launcher"
    current_path = INSTALL_ROOT / "current.json"
    _safe_root_program(launcher, executable=True)
    current_details = _regular_file(current_path)
    if current_details.st_uid != 0 or current_details.st_gid != 0:
        _fail("current selector is not root-owned")
    if current_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        _fail("current selector is writable outside root")
    if current_details.st_size > 65536:
        _fail("current selector is too large")
    try:
        current = json.loads(current_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("current selector is invalid JSON")
    version = current.get("version") if isinstance(current, dict) else None
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        _fail("current selector version is invalid")
    entrypoint = (
        INSTALL_ROOT / "versions" / version / "endpoint-agent" / "endpoint-agent"
    )
    _safe_root_program(entrypoint, executable=True)
    return version


def _root_secret(path: Path, label: str, representation: str) -> None:
    details = _regular_file(path)
    expected_mode = 0o600 if representation == "source" else 0o440
    if representation == "source":
        expected_uid = expected_gid = 0
    else:
        account = pwd.getpwnam("endpoint-agent")
        expected_uid, expected_gid = account.pw_uid, account.pw_gid
    if (
        details.st_uid != expected_uid
        or details.st_gid != expected_gid
        or stat.S_IMODE(details.st_mode) != expected_mode
    ):
        _fail(
            f"{label} has unsafe credential ownership or mode "
            f"({details.st_uid}:{details.st_gid}:{stat.S_IMODE(details.st_mode):03o})"
        )


def _service_secret(path: Path) -> bytes | None:
    try:
        details = os.lstat(path)
        account = pwd.getpwnam("endpoint-agent")
        raw = path.read_bytes()
    except (KeyError, OSError):
        return None
    if not (
        stat.S_ISREG(details.st_mode)
        and details.st_size == len(raw)
        and details.st_uid == account.pw_uid
        and details.st_gid == account.pw_gid
        and stat.S_IMODE(details.st_mode) == 0o600
    ):
        return None
    return raw


def _runtime_credential_is_valid(raw: bytes) -> bool:
    if raw.endswith(b"\r\n"):
        token = raw[:-2]
    elif raw.endswith(b"\n"):
        token = raw[:-1]
    else:
        token = raw
    return raw in {token, token + b"\n", token + b"\r\n"} and bool(
        DEVICE_CREDENTIAL.fullmatch(token)
    )


def _canonical_identity_is_valid(raw: bytes) -> bool:
    if not raw or len(raw) > 160:
        return False
    try:
        payload = json.loads(raw)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"device_id", "schema_version"}
            or payload.get("schema_version") != IDENTITY_SCHEMA
            or not isinstance(payload.get("device_id"), str)
        ):
            return False
        device_id = payload["device_id"]
        parsed = UUID(device_id)
        if (
            device_id != str(parsed)
            or parsed.variant != RFC_4122
            or parsed.version not in range(1, 6)
        ):
            return False
        canonical = json.dumps(
            {"device_id": device_id, "schema_version": IDENTITY_SCHEMA},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (AttributeError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        return False
    return raw == canonical


def _durable_credential() -> bool:
    credential = _service_secret(DATA_ROOT / "device-credential")
    identity = _service_secret(DATA_ROOT / "enrollment-identity.json")
    return (
        credential is not None
        and identity is not None
        and _runtime_credential_is_valid(credential)
        and _canonical_identity_is_valid(identity)
    )


def _claim_is_valid(path: Path, representation: str) -> bool:
    expected_mode = 0o600 if representation == "source" else 0o440
    try:
        details = os.lstat(path)
        if representation == "source":
            expected_uid = expected_gid = 0
        else:
            account = pwd.getpwnam("endpoint-agent")
            expected_uid, expected_gid = account.pw_uid, account.pw_gid
    except (KeyError, OSError):
        return False
    return (
        stat.S_ISREG(details.st_mode)
        and details.st_size > 0
        and details.st_uid == expected_uid
        and details.st_gid == expected_gid
        and stat.S_IMODE(details.st_mode) == expected_mode
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-unconfigured", action="store_true")
    parser.add_argument("--print-selected-version", action="store_true")
    parser.add_argument("--prepare-directories", action="store_true")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--ca", type=Path)
    parser.add_argument("--claim", type=Path)
    parser.add_argument("--credential-representation", choices=("source", "delegated"))
    args = parser.parse_args(argv)
    if args.prepare_directories:
        _prepare_runtime_directories()
        return 0
    version = _selected_release()
    if args.print_selected_version:
        print(version)
        return 0
    if args.allow_unconfigured:
        return 0
    if (
        args.config is None
        or args.ca is None
        or args.claim is None
        or args.credential_representation is None
    ):
        _fail("config, CA, claim, and credential representation are required")
    _root_secret(args.config, "endpoint config", args.credential_representation)
    _root_secret(args.ca, "endpoint CA", args.credential_representation)
    if not (
        _durable_credential()
        or _claim_is_valid(args.claim, args.credential_representation)
    ):
        _fail("neither durable credential nor enrollment claim is available")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
