"""Prepare private one-time pilot inputs on .19; never import/start Keycloak.

Default invocation prints a non-secret plan. With --apply, accept the fixed
LDAP bind credential as JSON on stdin through the approved SSH pipe. Generate
independent client/bootstrap secrets on-host and retain them in a root-only
environment file. No secret value is written to stdout/stderr or command argv.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys


TARGET = Path("/run/keycloak-provision-20261027")
BIND_DN = "CN=svc-keycloak-ldap,CN=Users,DC=sosnadmin,DC=local"
PILOT_DN = "CN=ssopilot-20261027,OU=TEST,DC=sosnadmin,DC=local"
CALLBACKS = {
    "helpdesk-web": "https://helpdesk.sosnadmin.local/api/web/session/oidc/callback",
    "endpoint-admin": "https://endpoint.sosnadmin.local/auth/admin/callback",
    "worktime-employee": "https://endpoint.sosnadmin.local/auth/employee/callback",
}


def _renderer():
    spec = importlib.util.spec_from_file_location("keycloak_realm_renderer", Path(__file__).with_name("render_realm.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_private(path: Path, content: str):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def prepare_files(target: Path, incoming: dict) -> dict[str, Path]:
    if not isinstance(incoming, dict) or set(incoming) != {"bind_dn", "bind_password"}:
        raise ValueError("Expected exactly the fixed bind identity and its password")
    if incoming["bind_dn"] != BIND_DN:
        raise ValueError("Only the dedicated unprivileged pilot bind identity is accepted")
    password = incoming["bind_password"]
    if not isinstance(password, str) or not re.fullmatch(r"[A-Za-z0-9_@!\-]{32,128}", password):
        raise ValueError("Invalid bind credential encoding or length")
    realm = _renderer().build_realm(CALLBACKS, PILOT_DN)
    values = {
        "SSO_LDAP_BIND_DN": BIND_DN,
        "SSO_LDAP_BIND_PASSWORD": password,
        "SSO_HELPDESK_CLIENT_SECRET": secrets.token_urlsafe(48),
        "SSO_ENDPOINT_CLIENT_SECRET": secrets.token_urlsafe(48),
        "SSO_WORKTIME_CLIENT_SECRET": secrets.token_urlsafe(48),
        "SSO_BOOTSTRAP_PASSWORD": secrets.token_urlsafe(48),
    }
    # Atomic directory claim: existing or partially prepared inputs must be
    # investigated, never replaced/rotated by a retry.
    target.mkdir(mode=0o700, parents=False, exist_ok=False)
    environment = target / "provision.env"
    realm_file = target / "sosnadmin-realm.json"
    _write_private(environment, "".join(f"{key}={value}\n" for key, value in values.items()))
    _write_private(realm_file, json.dumps(realm, ensure_ascii=False, indent=2) + "\n")
    return {"environment": environment, "realm": realm_file}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        print(json.dumps({"status": "PlanOnly", "directory": str(TARGET),
                          "bind_dn": BIND_DN, "pilot_dn": PILOT_DN,
                          "clients": list(CALLBACKS), "clients_enabled": False,
                          "keycloak_import_or_start": False}))
        return
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("Apply requires root on the approved Linux host")
    import grp
    group = grp.getgrnam("keycloak")
    addresses = subprocess.run(["hostname", "-I"], check=True, capture_output=True, text=True).stdout.split()
    if "192.168.100.19" not in addresses:
        raise SystemExit("Wrong deployment host")
    if subprocess.run(["systemctl", "is-active", "--quiet", "keycloak"]).returncode != 3:
        raise SystemExit("Keycloak must be installed and stopped before preparing initial import")
    if TARGET.exists() or TARGET.is_symlink():
        raise SystemExit("Pilot input directory exists; no input will be replaced")
    # Bounded input; malformed/oversize payloads receive generic errors without
    # echoing their contents. Do not pass the pipe through Tee-Object/loggers.
    try:
        payload = sys.stdin.buffer.read(4097)
        if len(payload) > 4096:
            raise ValueError("Oversize input")
        incoming = json.loads(payload.decode("utf-8-sig"))
        files = prepare_files(TARGET, incoming)
    except (ValueError, UnicodeError, OSError):
        raise SystemExit("Pilot input preparation failed; inspect only private file metadata") from None
    # systemd reads the root-only env and injects it into the one-shot importer.
    # Only the non-secret JSON is readable by the Keycloak Unix group.
    os.chown(TARGET, 0, group.gr_gid)
    os.chmod(TARGET, 0o750)
    os.chown(files["realm"], 0, group.gr_gid)
    os.chmod(files["realm"], 0o640)
    print(json.dumps({"status": "PreparedDisabledClients", "directory": str(TARGET),
                      "keycloak_import_or_start": False}))


if __name__ == "__main__":
    main()
