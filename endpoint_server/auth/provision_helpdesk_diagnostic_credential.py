"""Root-only rotation for the existing Helpdesk diagnostic integration identity."""
from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import stat
import sys
from uuid import uuid4

from sqlalchemy import select

from endpoint_server.auth.scopes import _load_service_principal
from endpoint_server.auth.service_tokens import create_service_credential, service_credential_is_active, service_credential_summary
from endpoint_server.audit.service import append_audit_event
from endpoint_server.config import Settings
from endpoint_server.db.models import ServiceClient, ServiceCredential
from endpoint_server.db.session import create_session_provider

REQUIRED_EXISTING_SCOPES = frozenset({"devices.read", "context.read", "context.collect", "operations.create", "operations.read"})
ADDED_SCOPES = frozenset({"modules.read", "module_operations.create", "module_operations.read"})
ALLOWED_SCOPES = REQUIRED_EXISTING_SCOPES | ADDED_SCOPES | {"operations.cancel", "device-binding.redeem"}


def diagnostic_scopes(existing):
    scopes = set(existing)
    if not REQUIRED_EXISTING_SCOPES <= scopes or not scopes <= ALLOWED_SCOPES:
        raise ValueError("existing scopes require independent review")
    return tuple(sorted(scopes | ADDED_SCOPES))


def _is_root():
    return os.name != "nt" and os.geteuid() == 0


def read_private_token_file(path: Path):
    if not path.is_absolute():
        raise ValueError("secret file must be absolute")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != 0 or facts.st_mode & 0o077 or facts.st_size > 256:
            raise ValueError("secret file must be root-owned and owner-only")
        return os.read(descriptor, 257).decode("ascii").strip()
    finally:
        os.close(descriptor)


def write_private_token_file(path: Path, token: str):
    if not path.is_absolute():
        raise ValueError("output file must be absolute")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as output:
            descriptor = -1
            output.write(token + "\n")
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


async def provision_helpdesk_diagnostic_credential(session, *, settings, current_token: str, output_path: Path, request_id: str):
    """Authenticate and retain the principal and rollback credential; issue only approved scopes."""
    written = False
    try:
        principal = await _load_service_principal(session, current_token, settings.service_token_pepper)
        if principal is None:
            raise ValueError("current integration credential is inactive")
        client = await session.scalar(select(ServiceClient).where(ServiceClient.id == principal.client.id).with_for_update())
        credential = await session.scalar(select(ServiceCredential).where(ServiceCredential.id == principal.credential.id).with_for_update().execution_options(populate_existing=True))
        if client is None or client.disabled_at is not None or credential is None or credential.service_client_id != client.id or not service_credential_is_active(credential):
            raise ValueError("integration identity changed")
        scopes = diagnostic_scopes(credential.scopes)
        issued = await create_service_credential(session, client.id, settings.service_token_pepper,
            actor_kind="system", actor_identifier="helpdesk-diagnostic-provision-cli", request_id=request_id,
            scopes=scopes, expires_at=credential.expires_at, commit=False)
        await append_audit_event(session, actor_kind="system", actor_identifier="helpdesk-diagnostic-provision-cli",
            action="helpdesk_diagnostic_credential.provisioned", object_kind="service_client", object_identifier=str(client.id),
            request_id=request_id, details={"added_scopes": sorted(ADDED_SCOPES), "rollback_credential_retained": True})
        write_private_token_file(output_path, issued.token)
        written = True
        await session.commit()
        return service_credential_summary(issued.record)
    except Exception:
        await session.rollback()
        if written:
            output_path.unlink(missing_ok=True)
        raise


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Invalid arguments\n")


async def _run(arguments=None):
    if not _is_root():
        raise PermissionError("root required")
    parser = _Parser(description="Rotate existing Helpdesk diagnostic integration access")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--current-token-file", type=Path)
    source.add_argument("--current-token-stdin", action="store_true")
    parser.add_argument("--output-file", type=Path, required=True)
    parsed = parser.parse_args(arguments)
    if parsed.current_token_file:
        token = read_private_token_file(parsed.current_token_file)
    else:
        if sys.stdin.isatty():
            raise ValueError("interactive secret input is forbidden")
        token = sys.stdin.read(257).strip()
    if not token or len(token) > 256:
        raise ValueError("invalid credential input")
    settings = Settings.from_environment()
    provider = create_session_provider(settings.database_url)
    try:
        async with provider() as session:
            await provision_helpdesk_diagnostic_credential(session, settings=settings, current_token=token,
                output_path=parsed.output_file, request_id=f"helpdesk-diagnostic-{uuid4().hex}")
    finally:
        await provider.close()
    print("Provisioned diagnostic access; existing rollback credential retained.")
    return 0


def main(arguments=None):
    try:
        return asyncio.run(_run(arguments))
    except Exception:
        # Neither credential material, paths, SQL parameters nor parser arguments reach stderr.
        print("Diagnostic credential provisioning failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
