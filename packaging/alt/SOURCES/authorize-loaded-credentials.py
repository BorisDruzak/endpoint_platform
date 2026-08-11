#!/usr/bin/python3
"""Materialize systemd credentials in the unit's ephemeral runtime directory."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import stat
import sys


CREDENTIALS_PARENT = Path("/run/credentials")
REQUIRED_CREDENTIALS = ("endpoint-agent-config", "endpoint-agent-ca")
OPTIONAL_CREDENTIALS = ("endpoint-enrollment-claim",)


def _fail(message: str) -> None:
    print(f"endpoint-agent credential authorization failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def _details(path: Path) -> os.stat_result:
    try:
        return os.lstat(path)
    except OSError:
        _fail("credential input is unavailable")


def _credential_directory(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.parent != CREDENTIALS_PARENT:
        _fail("unexpected credential directory")
    parent = _details(CREDENTIALS_PARENT)
    details = _details(path)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_gid != 0
        or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail("unsafe credential directory parent")
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != 0
        or stat.S_IMODE(details.st_mode) != 0o550
    ):
        _fail("unsafe credential directory")
    return path


def _read_source_file(path: Path) -> bytes:
    details = _details(path)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != 0
        or stat.S_IMODE(details.st_mode) != 0o440
        or details.st_size == 0
    ):
        _fail("unsafe loaded credential")
    try:
        return path.read_bytes()
    except OSError:
        _fail("loaded credential cannot be read")


def _runtime_directory(value: str, account: pwd.struct_passwd) -> Path:
    runtime_dir = Path(value)
    if runtime_dir != Path("/run/endpoint-agent-credentials"):
        _fail("unexpected runtime directory")
    details = _details(runtime_dir)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != account.pw_uid
        or details.st_gid != account.pw_gid
        or stat.S_IMODE(details.st_mode) != 0o750
    ):
        _fail("unsafe initial runtime directory")
    return runtime_dir


def _remove_previous_files(runtime_dir: Path, account: pwd.struct_passwd) -> None:
    allowed = set(REQUIRED_CREDENTIALS + OPTIONAL_CREDENTIALS)
    try:
        paths = tuple(runtime_dir.iterdir())
    except OSError:
        _fail("runtime directory cannot be inspected")
    for path in paths:
        details = _details(path)
        if (
            path.name not in allowed
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_gid != account.pw_gid
            or stat.S_IMODE(details.st_mode) != 0o440
        ):
            _fail("unsafe existing runtime credential")
        try:
            path.unlink()
        except OSError:
            _fail("stale runtime credential cannot be removed")


def _write_runtime_file(path: Path, raw: bytes, account: pwd.struct_passwd) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o440)
    except OSError:
        _fail("runtime credential cannot be created")
    try:
        os.fchown(descriptor, 0, account.pw_gid)
        os.fchmod(descriptor, 0o440)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except OSError:
        _fail("runtime credential cannot be written")
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials-directory", required=True)
    parser.add_argument("--runtime-directory", required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        _fail("requires root")
    credentials_dir = _credential_directory(args.credentials_directory)
    try:
        account = pwd.getpwnam("endpoint-agent")
    except KeyError:
        _fail("endpoint-agent account is unavailable")
    runtime_dir = _runtime_directory(args.runtime_directory, account)
    credentials: dict[str, bytes] = {}
    for name in REQUIRED_CREDENTIALS:
        credentials[name] = _read_source_file(credentials_dir / name)
    for name in OPTIONAL_CREDENTIALS:
        path = credentials_dir / name
        if path.exists():
            credentials[name] = _read_source_file(path)
    _remove_previous_files(runtime_dir, account)
    os.chown(runtime_dir, 0, account.pw_gid)
    os.chmod(runtime_dir, 0o550)
    for name, raw in credentials.items():
        _write_runtime_file(runtime_dir / name, raw, account)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
