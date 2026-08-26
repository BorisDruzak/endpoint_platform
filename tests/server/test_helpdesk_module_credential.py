"""Tests for the root-only Helpdesk module credential provisioning CLI."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from endpoint_server.auth.provision_helpdesk_module_credential import (
    HELPDESK_MODULE_SCOPES,
    HELPDESK_MODULE_SERVICE_CLIENT_IDENTIFIER,
    provision_helpdesk_module_credential,
    write_private_token_file,
)
from endpoint_server.db.models import ServiceClient


class _Session:
    def __init__(self) -> None:
        self.client: ServiceClient | None = None
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    async def scalar(self, statement: object) -> object | None:
        entity = statement.column_descriptions[0]["entity"]
        if entity is ServiceClient:
            return self.client
        raise AssertionError(f"unexpected scalar query: {entity}")

    def add(self, value: object) -> None:
        self.added.append(value)
        if isinstance(value, ServiceClient):
            self.client = value

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1


def test_helpdesk_module_credential_has_only_module_authoring_and_read_scopes() -> None:
    """The staging bridge must never receive a broad or execution grant."""
    assert HELPDESK_MODULE_SCOPES == (
        "module_operations.create",
        "module_operations.read",
        "modules.publish",
        "modules.read",
        "modules.validate",
        "modules.write",
    )


def test_write_private_token_file_creates_a_new_owner_only_file(tmp_path: Path) -> None:
    """Bearer material must never be printed or overwrite an existing file."""
    destination = tmp_path / "helpdesk-module-service-token"
    token = "svc_public.redacted-secret-material"

    write_private_token_file(destination, token)

    assert destination.read_text(encoding="ascii") == token + "\n"
    if os.name != "nt":
        assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_private_token_file(destination, token)


@pytest.mark.asyncio
async def test_provisioning_creates_the_fixed_client_and_commits_only_after_private_write(
    tmp_path: Path,
) -> None:
    """The service account must be narrowly identified and leave no bearer in output."""
    session = _Session()
    destination = tmp_path / "helpdesk-module-service-token"

    summary = await provision_helpdesk_module_credential(
        session,
        settings=SimpleNamespace(service_token_pepper=b"test-service-pepper"),
        output_path=destination,
        request_id="test-helpdesk-module-provisioning",
    )

    assert session.client is not None
    assert session.client.client_identifier == HELPDESK_MODULE_SERVICE_CLIENT_IDENTIFIER
    assert summary.scopes == HELPDESK_MODULE_SCOPES
    assert summary.token_prefix.startswith("svc_")
    assert session.commit_calls == 1
    assert session.rollback_calls == 0
    stored = destination.read_text(encoding="ascii")
    assert stored.startswith(summary.token_prefix + ".")
    assert summary.token_prefix != stored.strip()
