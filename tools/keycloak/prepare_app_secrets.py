"""Prepare disabled application candidates; never activate/restart applications.

Default invocation prints destinations only. --apply on .19 copies the private
provisioning input durably, creates exclusive backups/candidates and separate
Endpoint secret files. Existing active environment files remain byte-identical.
All secret generation/processing stays on host; no secret argv or output.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile


SUFFIX = ".sso-disabled-20261027"
BACKUP_SUFFIX = ".before-sso-20261027"


def parse_values(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue  # Preserve unrelated systemd quoting/continuation lines.
        name, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            if name in values:
                raise ValueError("Duplicate environment key")
            values[name] = value
    return values


def candidate_environment(original, updates):
    parse_values(original)
    retained = [line for line in original.splitlines()
                if not ("=" in line and line.split("=", 1)[0] in updates)]
    return "\n".join(retained).rstrip("\n") + "\n" + "".join(f"{key}={value}\n" for key, value in updates.items())


def write_exclusive(path, data, *, owner=None, mode=0o600):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".sso-private-", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            if os.name == "posix":
                os.fchmod(stream.fileno(), mode)
                if owner is not None:
                    os.fchown(stream.fileno(), *owner)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic publication without replacing a concurrently created target.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def prepare_delivery(root: Path, *, endpoint_owner=None, apply=True):
    def target(path):
        return root / path.lstrip("/")
    provision = target("/run/keycloak-provision-20261027/provision.env")
    endpoint_env = target("/etc/endpoint-platform/endpoint-platform.env")
    helpdesk_env = target("/etc/helpdesk/helpdesk.env")
    for path in (provision, endpoint_env, helpdesk_env):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Expected physical private deployment inputs")
    raw_provision = provision.read_bytes()
    endpoint_original, helpdesk_original = endpoint_env.read_bytes(), helpdesk_env.read_bytes()
    values = parse_values(raw_provision.decode("utf-8"))
    for name in ("SSO_HELPDESK_CLIENT_SECRET", "SSO_ENDPOINT_CLIENT_SECRET", "SSO_WORKTIME_CLIENT_SECRET"):
        if not re.fullmatch(r"[A-Za-z0-9_@!\-]{43,256}", values.get(name, "")):
            raise ValueError("Invalid confidential client secret encoding")
    if len({values[name] for name in ("SSO_HELPDESK_CLIENT_SECRET", "SSO_ENDPOINT_CLIENT_SECRET", "SSO_WORKTIME_CLIENT_SECRET")}) != 3:
        raise ValueError("Confidential clients must have independent secrets")
    for text, setting in ((endpoint_original.decode("utf-8"), "ENDPOINT_SSO_ENABLED"),
                          (helpdesk_original.decode("utf-8"), "OIDC_ENABLED")):
        if parse_values(text).get(setting, "false").strip('"\'').lower() not in {"false", "0", ""}:
            raise ValueError("Application SSO must remain disabled during preparation")
    # Fernet.generate_key() is urlsafe Base64 of32 CSPRNG bytes. Generate two
    # independent compatible keys using stdlib, validated by Fernet in tests.
    endpoint_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    helpdesk_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    identity_credential = secrets.token_urlsafe(48)
    secret_root = "/etc/endpoint-platform/secrets/"
    secret_values = {
        secret_root + "oidc-admin-client-secret": values["SSO_ENDPOINT_CLIENT_SECRET"],
        secret_root + "oidc-employee-client-secret": values["SSO_WORKTIME_CLIENT_SECRET"],
        secret_root + "oidc-token-encryption-key": endpoint_key,
        secret_root + "helpdesk-identity-credential": identity_credential,
    }
    endpoint_updates = {
        "ENDPOINT_SSO_ENABLED": "false", "ENDPOINT_WORKTIME_ENABLED": "false",
        "OIDC_ISSUER": "https://sso.sosnadmin.local/realms/sosnadmin",
        "OIDC_EMPLOYEE_CLIENT_ID": "worktime-employee", "OIDC_ADMIN_CLIENT_ID": "endpoint-admin",
        "OIDC_EMPLOYEE_CLIENT_SECRET_FILE": secret_root + "oidc-employee-client-secret",
        "OIDC_ADMIN_CLIENT_SECRET_FILE": secret_root + "oidc-admin-client-secret",
        "OIDC_ADMIN_REQUIRED_ACR": "urn:sosnadmin:loa:2",
        "OIDC_ENCRYPTION_KEY_FILE": secret_root + "oidc-token-encryption-key",
        "HELPDESK_IDENTITY_BASE_URL": "https://helpdesk.sosnadmin.local",
        "HELPDESK_IDENTITY_CREDENTIAL_FILE": secret_root + "helpdesk-identity-credential",
        "ENDPOINT_SSO_CA_FILE": "/etc/endpoint-platform/sosnadmin-local-ca.crt",
    }
    helpdesk_updates = {
        "OIDC_ENABLED": "false", "OIDC_ISSUER": "https://sso.sosnadmin.local/realms/sosnadmin",
        "OIDC_CLIENT_ID": "helpdesk-web", "OIDC_CLIENT_SECRET": values["SSO_HELPDESK_CLIENT_SECRET"],
        "OIDC_REDIRECT_URI": "https://helpdesk.sosnadmin.local/api/web/session/oidc/callback",
        "OIDC_TOKEN_ENCRYPTION_KEY": helpdesk_key, "OIDC_PRIVILEGED_ACR": "urn:sosnadmin:loa:2",
        "OIDC_AD_GUID_CLAIM": "ad_object_guid", "OIDC_CA_FILE": "/etc/helpdesk/sso-ca.crt",
        "IDENTITY_RESOLVE_SERVICE_TOKEN": identity_credential,
        "WORKTIME_PORTAL_URL": "https://endpoint.sosnadmin.local/employee",
    }
    candidates = {
        endpoint_env.with_name(endpoint_env.name + SUFFIX): candidate_environment(endpoint_original.decode("utf-8"), endpoint_updates).encode("utf-8"),
        helpdesk_env.with_name(helpdesk_env.name + SUFFIX): candidate_environment(helpdesk_original.decode("utf-8"), helpdesk_updates).encode("utf-8"),
    }
    regular = {
        target("/etc/keycloak/pilot-provision-20261027.env"): raw_provision,
        endpoint_env.with_name(endpoint_env.name + BACKUP_SUFFIX): endpoint_original,
        helpdesk_env.with_name(helpdesk_env.name + BACKUP_SUFFIX): helpdesk_original,
        **candidates,
    }
    public_ca = target("/etc/helpdesk/sso-ca.crt")
    ca_bytes = target("/etc/endpoint-platform/sosnadmin-local-ca.crt").read_bytes()
    destinations = list(regular) + [target(name) for name in secret_values] + [public_ca]
    if any(path.exists() or path.is_symlink() for path in destinations):
        raise FileExistsError("Delivery input/candidate exists; never rotate or overwrite on retry")
    for path in destinations:
        if path.parent.is_symlink() or not path.parent.is_dir():
            raise ValueError("Expected existing physical application deployment directories")
    if not apply:
        return {"status": "DisabledApplicationCandidateInputsVerified", "active_environments_changed": False,
                "applications_restarted": False, "keycloak_clients_changed": False,
                "private_files_written": 0}
    for path, data in regular.items():
        write_exclusive(path, data)
    for name, value in secret_values.items():
        write_exclusive(target(name), (value + "\n").encode("ascii"), owner=endpoint_owner)
    write_exclusive(public_ca, ca_bytes, mode=0o644)
    if endpoint_env.read_bytes() != endpoint_original or helpdesk_env.read_bytes() != helpdesk_original:
        raise ValueError("Active environment changed concurrently; candidates require review")
    return {"status": "DisabledApplicationCandidatesPrepared", "active_environments_changed": False,
            "applications_restarted": False, "keycloak_clients_changed": False,
            "durable_provision_backup": True, "separate_endpoint_secret_files": 4}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Prepare exclusive files/candidates only; never install active envs")
    parser.add_argument("--check", action="store_true", help="Validate live private inputs/destinations without writing")
    args = parser.parse_args()
    if args.apply and args.check:
        raise ValueError("Choose validation or preparation")
    if not args.apply and not args.check:
        print(json.dumps({"status": "PlanOnly", "active_environments_changed": False,
                          "candidate_suffix": SUFFIX, "application_flags_enabled": False,
                          "durable_provision_backup": "/etc/keycloak/pilot-provision-20261027.env"}))
        return
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Preparation requires root on the approved Linux host")
    import pwd
    owner = pwd.getpwnam("endpoint-platform")
    addresses = subprocess.run(["hostname", "-I"], check=True, capture_output=True, text=True).stdout.split()
    if "192.168.100.19" not in addresses:
        raise ValueError("Wrong deployment host")
    for path in (Path("/run/keycloak-provision-20261027/provision.env"),
                 Path("/etc/endpoint-platform/endpoint-platform.env"), Path("/etc/helpdesk/helpdesk.env")):
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o777 != 0o600:
            raise ValueError("Existing private environment metadata differs from reviewed policy")
    print(json.dumps(prepare_delivery(Path("/"), endpoint_owner=(owner.pw_uid, owner.pw_gid), apply=args.apply)))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"status": "ApplicationSecretPreparationRefused", "secret_values_logged": False}))
        raise SystemExit(1) from None
