#!/usr/bin/python3
"""Grant the agent read-only access to systemd's private credential copies."""

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


def _authorize_file(path: Path, account: pwd.struct_passwd) -> None:
    details = _details(path)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_gid != 0
        or stat.S_IMODE(details.st_mode) != 0o440
    ):
        _fail("unsafe loaded credential")
    os.chown(path, 0, account.pw_gid)
    os.chmod(path, 0o440)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials-directory", required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        _fail("requires root")
    credentials_dir = _credential_directory(args.credentials_directory)
    try:
        account = pwd.getpwnam("endpoint-agent")
    except KeyError:
        _fail("endpoint-agent account is unavailable")
    for name in REQUIRED_CREDENTIALS:
        _authorize_file(credentials_dir / name, account)
    for name in OPTIONAL_CREDENTIALS:
        path = credentials_dir / name
        if path.exists():
            _authorize_file(path, account)
    os.chown(credentials_dir, 0, account.pw_gid)
    os.chmod(credentials_dir, 0o550)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
