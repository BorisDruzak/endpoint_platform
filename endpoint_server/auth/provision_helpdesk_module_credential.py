"""Root-only provisioning of the staging Helpdesk module service credential."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Protocol, Sequence
from uuid import uuid4

from sqlalchemy import select

from endpoint_server.auth.scopes import (
    MODULE_OPERATIONS_CREATE_SCOPE,
    MODULE_OPERATIONS_READ_SCOPE,
    MODULES_PUBLISH_SCOPE,
    MODULES_READ_SCOPE,
    MODULES_VALIDATE_SCOPE,
    MODULES_WRITE_SCOPE,
)
from endpoint_server.auth.service_tokens import (
    ServiceCredentialSummary,
    create_service_credential,
    service_credential_summary,
)
from endpoint_server.config import Settings
from endpoint_server.db.models import ServiceClient
from endpoint_server.db.session import create_session_provider


HELPDESK_MODULE_SERVICE_CLIENT_IDENTIFIER = "helpdesk-module-staging"
_HELPDESK_MODULE_SERVICE_DISPLAY_NAME = "Helpdesk Endpoint Module workbench (staging)"
HELPDESK_MODULE_SCOPES = (
    MODULE_OPERATIONS_CREATE_SCOPE,
    MODULE_OPERATIONS_READ_SCOPE,
    MODULES_PUBLISH_SCOPE,
    MODULES_READ_SCOPE,
    MODULES_VALIDATE_SCOPE,
    MODULES_WRITE_SCOPE,
)


class _ProvisioningSession(Protocol):
    async def scalar(self, statement: object) -> object | None: ...

    def add(self, instance: object) -> None: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


class _SecretSafeArgumentParser(argparse.ArgumentParser):
    """Avoid reflecting invalid argument values into CLI stderr."""

    def error(self, _: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Accept only a root-controlled private destination path."""
    parser = _SecretSafeArgumentParser(
        prog="python -m endpoint_server.auth.provision_helpdesk_module_credential",
        description="Provision the staging Helpdesk module service credential",
    )
    parser.add_argument("--output-file", required=True, type=Path)
    return parser.parse_args(arguments)


def write_private_token_file(destination: Path, token: str) -> None:
    """Write bearer material once to a new owner-only regular file."""
    if not destination.is_absolute():
        raise ValueError("output file path must be absolute")
    if not token:
        raise ValueError("service credential must not be empty")
    try:
        token.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("service credential must be ASCII") from error

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as output:
            descriptor = -1
            output.write(token)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


async def _helpdesk_module_service_client(
    session: _ProvisioningSession,
) -> ServiceClient:
    client = await session.scalar(
        select(ServiceClient).where(
            ServiceClient.client_identifier
            == HELPDESK_MODULE_SERVICE_CLIENT_IDENTIFIER
        )
    )
    if client is None:
        client = ServiceClient(
            id=uuid4(),
            client_identifier=HELPDESK_MODULE_SERVICE_CLIENT_IDENTIFIER,
            display_name=_HELPDESK_MODULE_SERVICE_DISPLAY_NAME,
            disabled_at=None,
        )
        session.add(client)
    assert isinstance(client, ServiceClient)
    if client.disabled_at is not None:
        raise RuntimeError("Helpdesk module service client is disabled")
    return client


async def provision_helpdesk_module_credential(
    session: _ProvisioningSession,
    *,
    settings: Settings,
    output_path: Path,
    request_id: str,
) -> ServiceCredentialSummary:
    """Persist a narrow credential after its bearer reaches only a private file."""
    token_written = False
    try:
        client = await _helpdesk_module_service_client(session)
        issued = await create_service_credential(
            session,  # type: ignore[arg-type]
            client.id,
            settings.service_token_pepper,
            actor_kind="system",
            actor_identifier="helpdesk-module-provision-cli",
            request_id=request_id,
            scopes=HELPDESK_MODULE_SCOPES,
            commit=False,
        )
        write_private_token_file(output_path, issued.token)
        token_written = True
        await session.commit()
        return service_credential_summary(issued.record)
    except Exception:
        await session.rollback()
        if token_written:
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _is_root() -> bool:
    return os.name != "nt" and os.geteuid() == 0


async def _run(arguments: Sequence[str] | None = None) -> int:
    parsed = parse_arguments(arguments)
    if not _is_root():
        raise PermissionError("Helpdesk module credential provisioning requires root")
    settings = Settings.from_environment()
    provider = create_session_provider(settings.database_url)
    try:
        async with provider() as session:
            await provision_helpdesk_module_credential(
                session,
                settings=settings,
                output_path=parsed.output_file,
                request_id=f"helpdesk-module-provision-{uuid4().hex}",
            )
    finally:
        await provider.close()
    print("Provisioned Helpdesk module service credential.")
    return 0


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the root-only provisioner without exposing bearer material."""
    return asyncio.run(_run(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
