"""Interactive first-administrator bootstrap command."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence
from typing import Protocol

from sqlalchemy import func, select, text

from endpoint_server.config import Settings
from endpoint_server.db.models import AdminUser
from endpoint_server.db.session import create_session_provider

from .passwords import hash_password


_FIRST_ADMIN_LOCK_KEY = 0x454E445041444D49


class _BootstrapSession(Protocol):
    async def execute(
        self, statement: object, parameters: object | None = None
    ) -> object: ...

    async def scalar(self, statement: object) -> int | None: ...

    def add(self, instance: object) -> None: ...

    async def commit(self) -> None: ...


class _SecretSafeArgumentParser(argparse.ArgumentParser):
    """Reject invalid CLI shapes without echoing possible credential material."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse only the non-secret administrator username."""
    parser = _SecretSafeArgumentParser(
        prog="python -m endpoint_server.auth.bootstrap_admin",
        description="Create the first administrator",
    )
    parser.add_argument("username", help="administrator login name")
    return parser.parse_args(arguments)


def read_interactive_password() -> str:
    """Read and confirm a password only while attached to an interactive terminal."""
    if not sys.stdin.isatty():
        raise RuntimeError("bootstrap password requires an interactive terminal")
    password = getpass.getpass("Administrator password: ")
    confirmation = getpass.getpass("Confirm administrator password: ")
    if not password:
        raise RuntimeError("administrator password must not be empty")
    if not secrets_compare(password, confirmation):
        raise RuntimeError("administrator password confirmation does not match")
    return password


def secrets_compare(left: str, right: str) -> bool:
    """Compare password confirmation without early-exit string comparison."""
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


async def bootstrap_first_admin(
    session: _BootstrapSession, username: str, password: str
) -> AdminUser:
    """Persist the first administrator, storing only an Argon2id digest."""
    normalized_username = username.strip()
    if not normalized_username or len(normalized_username) > 128:
        raise ValueError("username must contain between 1 and 128 characters")
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": _FIRST_ADMIN_LOCK_KEY},
    )
    existing_admins = await session.scalar(select(func.count(AdminUser.id)))
    if existing_admins:
        raise RuntimeError("an administrator already exists")

    user = AdminUser(
        username=normalized_username,
        password_digest=hash_password(password),
        disabled_at=None,
    )
    session.add(user)
    await session.commit()
    return user


async def _run(arguments: Sequence[str] | None = None) -> int:
    parsed = parse_arguments(arguments)
    password = read_interactive_password()
    settings = Settings.from_environment()
    provider = create_session_provider(settings.database_url)
    try:
        async with provider() as session:
            await bootstrap_first_admin(session, parsed.username, password)
    finally:
        await provider.close()
    return 0


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the interactive bootstrap command."""
    return asyncio.run(_run(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
