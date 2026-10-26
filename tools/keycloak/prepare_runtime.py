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
import tempfile


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


def repair_prepared_realm(path: Path, *, apply=False):
    """Remove only known API-only component fields from the original pilot JSON.

    No secret environment is read. Exact comparison with the disabled pilot
    renderer rejects unrelated/sensitive edits before any backup or replacement.
    """
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected the physical prepared pilot realm file")
    backup = path.with_suffix(".before-export-shape.json")
    if backup.exists() or backup.is_symlink():
        raise FileExistsError("Prepared realm backup already exists; no overwrite")
    original = path.read_bytes()
    realm = json.loads(original.decode("utf-8"))
    removed = 0
    def strip_api_fields(collection):
        nonlocal removed
        if not isinstance(collection, dict):
            raise ValueError("Expected exported component map")
        for provider_type, components in collection.items():
            if not isinstance(components, list):
                raise ValueError("Expected exported component list")
            for component in components:
                if not isinstance(component, dict):
                    raise ValueError("Expected exported component object")
                if "providerType" in component:
                    if component["providerType"] != provider_type:
                        raise ValueError("API component type disagrees with export map")
                    del component["providerType"]
                    removed += 1
                strip_api_fields(component.get("subComponents", {}))
    strip_api_fields(realm.get("components"))
    renderer = _renderer()
    renderer.validate_component_exports(realm["components"])
    if removed == 0 or realm != renderer.build_realm(CALLBACKS, PILOT_DN):
        raise ValueError("Only the original disabled placeholder pilot realm can be repaired")
    if not apply:
        return {"status": "RepairPlanOnly", "removed_fields": removed}
    metadata = path.stat()
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(descriptor, "wb") as stream:
        if os.name == "posix":
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), 0o640)
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         prefix=".realm-export-shape-", dir=path.parent,
                                         delete=False) as stream:
            temporary = Path(stream.name)
            if os.name == "posix":
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                os.fchmod(stream.fileno(), 0o640)
            json.dump(realm, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != original:
            raise ValueError("Prepared realm changed concurrently; refusing replacement")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return {"status": "PreparedRealmExportShapeRepaired", "removed_fields": removed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--repair-prepared-realm", action="store_true",
                        help="Plan/repair only the existing disabled realm JSON; never rotate secrets")
    args = parser.parse_args()
    if not args.apply and not args.repair_prepared_realm:
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
    if args.repair_prepared_realm:
        path = TARGET / "sosnadmin-realm.json"
        if TARGET.is_symlink() or not TARGET.is_dir():
            raise SystemExit("Expected the original physical pilot preparation directory")
        metadata = path.stat(follow_symlinks=False)
        if metadata.st_uid != 0 or metadata.st_gid != group.gr_gid or metadata.st_mode & 0o777 != 0o640:
            raise SystemExit("Prepared realm must remain root:keycloak 0640")
        try:
            result = repair_prepared_realm(path, apply=args.apply)
        except (ValueError, UnicodeError, OSError):
            raise SystemExit("Prepared realm repair refused; inspect only private file metadata") from None
        print(json.dumps(result))
        return
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
