"""Tests for the root-only Helpdesk module credential provisioning CLI."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

import endpoint_server.auth.provision_helpdesk_module_credential as credential_module
from endpoint_server.auth.provision_helpdesk_module_credential import (
    HELPDESK_MODULE_SCOPES,
    HELPDESK_MODULE_SERVICE_CLIENT_IDENTIFIER,
    provision_helpdesk_module_credential,
    write_private_token_file,
)
from endpoint_server.db.models import AuditEvent, ServiceClient, ServiceCredential


class _Session:
    def __init__(self) -> None:
        self.client: ServiceClient | None = None
        self.credentials: list[ServiceCredential] = []
        self.added: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    async def scalar(self, statement: object) -> object | None:
        entity = statement.column_descriptions[0]["entity"]
        if entity is ServiceClient:
            return self.client
        raise AssertionError(f"unexpected scalar query: {entity}")

    async def scalars(self, statement: object) -> object:
        entity = statement.column_descriptions[0]["entity"]
        assert entity is ServiceCredential

        class _Rows:
            def __init__(self, values: list[ServiceCredential]) -> None:
                self.values = values

            def all(self) -> list[ServiceCredential]:
                return self.values

        return _Rows(
            [credential for credential in self.credentials if credential.revoked_at is None]
        )

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
    assert session.client.id is not None
    assert summary.scopes == HELPDESK_MODULE_SCOPES
    assert summary.token_prefix.startswith("svc_")
    assert session.commit_calls == 1
    assert session.rollback_calls == 0
    stored = destination.read_text(encoding="ascii")
    assert stored.startswith(summary.token_prefix + ".")
    assert summary.token_prefix != stored.strip()


@pytest.mark.asyncio
async def test_revocation_disables_all_active_helpdesk_module_credentials_and_audits() -> None:
    """Closure must revoke the staging bridge without reprinting bearer material."""
    session = _Session()
    client = ServiceClient(
        id=uuid4(),
        client_identifier=HELPDESK_MODULE_SERVICE_CLIENT_IDENTIFIER,
        display_name="Helpdesk Endpoint Module workbench (staging)",
        disabled_at=None,
    )
    session.client = client
    active = ServiceCredential(
        id=uuid4(),
        service_client_id=client.id,
        credential_identifier="a" * 32,
        token_prefix="svc_" + "a" * 32,
        secret_digest="a" * 64,
        scopes=list(HELPDESK_MODULE_SCOPES),
        expires_at=None,
        revoked_at=None,
    )
    already_revoked = ServiceCredential(
        id=uuid4(),
        service_client_id=client.id,
        credential_identifier="b" * 32,
        token_prefix="svc_" + "b" * 32,
        secret_digest="b" * 64,
        scopes=list(HELPDESK_MODULE_SCOPES),
        expires_at=None,
        revoked_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    session.credentials = [active, already_revoked]

    revoke = getattr(credential_module, "revoke_helpdesk_module_credentials", None)
    assert callable(revoke)
    revoked = await revoke(
        session,
        request_id="test-helpdesk-module-revocation",
        now=datetime(2026, 8, 27, tzinfo=UTC),
    )

    assert revoked == 1
    assert active.revoked_at == datetime(2026, 8, 27, tzinfo=UTC)
    assert already_revoked.revoked_at == datetime(2026, 8, 1, tzinfo=UTC)
    audits = [value for value in session.added if isinstance(value, AuditEvent)]
    assert [audit.action for audit in audits] == [
        "helpdesk_module_credential.revoked"
    ]
    assert audits[0].details == {"scopes": list(HELPDESK_MODULE_SCOPES)}
    assert session.commit_calls == 1
