"""Diagnostic access cannot acquire module authoring or change its principal."""
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4
from datetime import datetime, UTC
import endpoint_server.auth.provision_helpdesk_diagnostic_credential as cli
from endpoint_server.db.models import ServiceClient, ServiceCredential, AuditEvent

from endpoint_server.auth.provision_helpdesk_diagnostic_credential import diagnostic_scopes

BASE = ("devices.read", "context.read", "context.collect", "operations.create", "operations.read", "operations.cancel")


def test_diagnostic_rotation_does_not_grant_authoring_scopes():
    scopes = diagnostic_scopes(BASE)
    assert set(BASE) <= set(scopes)
    assert {"modules.read", "module_operations.create", "module_operations.read"} <= set(scopes)
    assert not {"modules.write", "modules.validate", "modules.publish"} & set(scopes)


@pytest.mark.parametrize("scope", ["modules.write", "modules.validate", "modules.publish", "unknown.scope"])
def test_unexpected_existing_grants_require_review(scope):
    with pytest.raises(ValueError):
        diagnostic_scopes((*BASE, scope))


@pytest.mark.asyncio
@pytest.mark.parametrize("commit_fails", [False, True])
async def test_rotation_preserves_client_identity_and_existing_operation_reads(tmp_path, monkeypatch, commit_fails):
    client = ServiceClient(id=uuid4(), client_identifier="existing-integration", display_name="Integration", disabled_at=None)
    old = ServiceCredential(id=uuid4(), service_client_id=client.id, credential_identifier="a"*32, token_prefix="svc_"+"a"*32,
        secret_digest="a"*64, scopes=list(BASE), revoked_at=None, expires_at=datetime(2099,1,1,tzinfo=UTC))
    added=[]
    session=SimpleNamespace(scalar=AsyncMock(side_effect=[client,old]), add=added.append, commit=AsyncMock(),rollback=AsyncMock())
    if commit_fails:session.commit.side_effect=RuntimeError("transaction failed")
    monkeypatch.setattr(cli,"_load_service_principal",AsyncMock(return_value=SimpleNamespace(client=client,credential=old)))
    def write(path, token):path.write_text(token,encoding="ascii")
    monkeypatch.setattr(cli,"write_private_token_file",write)
    path=tmp_path/"issued"
    kwargs=dict(settings=SimpleNamespace(service_token_pepper=b"synthetic-test-only"),current_token="synthetic-current",output_path=path,request_id="test")
    if commit_fails:
        with pytest.raises(RuntimeError):await cli.provision_helpdesk_diagnostic_credential(session,**kwargs)
        session.rollback.assert_awaited_once();assert not path.exists()
    else:
        result=await cli.provision_helpdesk_diagnostic_credential(session,**kwargs)
        assert result.service_client_id==client.id and set(BASE)<=set(result.scopes)
        assert result.expires_at==old.expires_at
        assert [x.action for x in added if isinstance(x,AuditEvent)]==["service_credential.created","helpdesk_diagnostic_credential.provisioned"]
    assert old.revoked_at is None and old.scopes==list(BASE)
    assert not any(isinstance(x,ServiceClient) for x in added)


def test_cli_rejects_non_root_without_reading_secrets(monkeypatch,capsys):
    monkeypatch.setattr(cli,"_is_root",lambda:False)
    assert cli.main(["--current-token-stdin","--output-file","private-path"])==1
    assert "private-path" not in capsys.readouterr().err


@pytest.mark.skipif(__import__("os").name=="nt",reason="POSIX private file permissions")
def test_private_output_rejects_overwrite_and_symlink(tmp_path):
    path=tmp_path/"issued"
    cli.write_private_token_file(path,"synthetic-value")
    assert path.stat().st_mode&0o777==0o600
    with pytest.raises(FileExistsError):cli.write_private_token_file(path,"other")
    linked=tmp_path/"linked";linked.symlink_to(path)
    with pytest.raises(FileExistsError):cli.write_private_token_file(linked,"other")
    assert path.read_text()=="synthetic-value\n"
