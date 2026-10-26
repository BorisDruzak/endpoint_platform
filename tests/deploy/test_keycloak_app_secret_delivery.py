import importlib.util
from pathlib import Path

from cryptography.fernet import Fernet
import pytest


def module():
    spec = importlib.util.spec_from_file_location("app_secret_delivery", Path("tools/keycloak/prepare_app_secrets.py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def setup_root(tmp_path):
    for folder in ("run/keycloak-provision-20261027", "etc/keycloak", "etc/endpoint-platform/secrets", "etc/helpdesk"):
        (tmp_path / folder).mkdir(parents=True, exist_ok=True)
    provision = "\n".join(f"{key}=TEST_ONLY_{key}_abcdefghijklmnopqrstuvwxyz1234567890" for key in (
        "SSO_HELPDESK_CLIENT_SECRET", "SSO_ENDPOINT_CLIENT_SECRET", "SSO_WORKTIME_CLIENT_SECRET", "SSO_BOOTSTRAP_PASSWORD")) + "\n"
    (tmp_path / "run/keycloak-provision-20261027/provision.env").write_text(provision)
    (tmp_path / "etc/endpoint-platform/endpoint-platform.env").write_text("DATABASE_URL=existing-test-only\nENDPOINT_SSO_ENABLED=false\nENDPOINT_WORKTIME_ENABLED=false\n")
    (tmp_path / "etc/helpdesk/helpdesk.env").write_text("DATABASE_URL=other-existing-test-only\nOIDC_ENABLED=false\n")
    (tmp_path / "etc/endpoint-platform/sosnadmin-local-ca.crt").write_text("DUMMY_PUBLIC_TEST_CA_ONLY\n")
    return provision


def test_delivery_prepares_disabled_candidates_and_preserves_active_configuration(tmp_path):
    runtime = module()
    provision = setup_root(tmp_path)
    endpoint = tmp_path / "etc/endpoint-platform/endpoint-platform.env"
    helpdesk = tmp_path / "etc/helpdesk/helpdesk.env"
    before = (endpoint.read_bytes(), helpdesk.read_bytes())
    result = runtime.prepare_delivery(tmp_path)
    assert result["status"] == "DisabledApplicationCandidatesPrepared"
    assert (endpoint.read_bytes(), helpdesk.read_bytes()) == before
    assert (tmp_path / "etc/keycloak/pilot-provision-20261027.env").read_text() == provision
    endpoint_candidate = endpoint.with_name(endpoint.name + ".sso-disabled-20261027").read_text()
    helpdesk_candidate = helpdesk.with_name(helpdesk.name + ".sso-disabled-20261027").read_text()
    assert "ENDPOINT_SSO_ENABLED=false" in endpoint_candidate
    assert "ENDPOINT_WORKTIME_ENABLED=false" in endpoint_candidate
    assert "OIDC_ENABLED=false" in helpdesk_candidate
    assert "OIDC_CLIENT_ID=helpdesk-web" in helpdesk_candidate
    assert "OIDC_EMPLOYEE_CLIENT_ID=worktime-employee" in endpoint_candidate
    endpoint_key = (tmp_path / "etc/endpoint-platform/secrets/oidc-token-encryption-key").read_bytes().strip()
    helpdesk_key = next(line.split("=", 1)[1] for line in helpdesk_candidate.splitlines() if line.startswith("OIDC_TOKEN_ENCRYPTION_KEY="))
    Fernet(endpoint_key)
    Fernet(helpdesk_key.encode())
    assert endpoint_key != helpdesk_key.encode()
    identity = (tmp_path / "etc/endpoint-platform/secrets/helpdesk-identity-credential").read_text().strip()
    assert len(identity) >= 43
    assert "IDENTITY_RESOLVE_SERVICE_TOKEN=" + identity in helpdesk_candidate
    assert identity not in str(result)
    with pytest.raises(FileExistsError):
        runtime.prepare_delivery(tmp_path)


def test_active_flags_or_duplicate_keys_are_refused_before_writes(tmp_path):
    runtime = module()
    setup_root(tmp_path)
    endpoint = tmp_path / "etc/endpoint-platform/endpoint-platform.env"
    endpoint.write_text("ENDPOINT_SSO_ENABLED=true\n")
    with pytest.raises(ValueError):
        runtime.prepare_delivery(tmp_path)
    assert not (tmp_path / "etc/keycloak/pilot-provision-20261027.env").exists()


def test_delivery_preflight_writes_no_private_file(tmp_path):
    runtime = module()
    setup_root(tmp_path)
    before = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*") if path.is_file())
    result = runtime.prepare_delivery(tmp_path, apply=False)
    after = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*") if path.is_file())
    assert result["private_files_written"] == 0
    assert before == after
