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


INSTALL_ROOT = Path("/opt/endpoint-agent")
DATA_ROOT = Path("/var/lib/endpoint-agent")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
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


def _root_secret(path: Path, label: str) -> None:
    details = _regular_file(path)
    if details.st_uid != 0 or details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        _fail(f"{label} must be root-owned and mode 0600")


def _durable_credential() -> bool:
    path = DATA_ROOT / "device-credential"
    try:
        details = os.lstat(path)
        account = pwd.getpwnam("endpoint-agent")
    except (KeyError, OSError):
        return False
    return (
        stat.S_ISREG(details.st_mode)
        and details.st_size > 0
        and details.st_uid == account.pw_uid
        and details.st_gid == account.pw_gid
        and stat.S_IMODE(details.st_mode) == 0o600
    )


def _loaded_claim(path: Path) -> bool:
    try:
        details = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(details.st_mode)
        and details.st_size > 0
        and not details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-unconfigured", action="store_true")
    parser.add_argument("--print-selected-version", action="store_true")
    parser.add_argument("--prepare-directories", action="store_true")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--ca", type=Path)
    parser.add_argument("--claim", type=Path)
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
    if args.config is None or args.ca is None or args.claim is None:
        _fail("config, CA, and claim credential paths are required")
    _root_secret(args.config, "endpoint config")
    _root_secret(args.ca, "endpoint CA")
    if not (_durable_credential() or _loaded_claim(args.claim)):
        _fail("neither durable credential nor enrollment claim is available")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
