"""Read-only preflight for a real installed ALT Endpoint agent."""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

from tools.canary.evidence_models import write_secure_json


class CanaryPreflightError(RuntimeError):
    """The installed agent does not meet a fail-closed canary invariant."""


_REVISION = re.compile(r"[0-9a-f]{7,64}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_REQUIRED_UNIT_VALUES = {
    "User": "endpoint-agent",
    "Group": "endpoint-agent",
    "Restart": "on-failure",
    "NoNewPrivileges": "true",
    "ProtectSystem": "strict",
}
_START_WRAPPER_PATH = "/usr/lib/endpoint-agent/start-endpoint-agent"
_START_WRAPPER = Path(_START_WRAPPER_PATH)
_DIRECT_LAUNCHER_FRAGMENTS = (
    "/opt/endpoint-agent/launcher",
    "--no-gui",
    "--transport-mode gateway_wss",
    "--no-migration-http-pull-fallback",
)
_WRAPPER_REQUIRED_FRAGMENTS = (
    'CHECKER = Path("/usr/lib/endpoint-agent/check-start-prerequisites")',
    'LAUNCHER = Path("/opt/endpoint-agent/launcher")',
    "os.execv(",
    '"--no-gui"',
    '"--transport-mode"',
    '"gateway_wss"',
    '"--no-migration-http-pull-fallback"',
    '"--data-dir"',
    '"/var/lib/endpoint-agent"',
    '"--install-root"',
    '"/opt/endpoint-agent"',
)


def _regular_file(path: Path, *, name: str) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise CanaryPreflightError(f"{name} is missing") from error
    except PermissionError as error:
        raise CanaryPreflightError(f"{name} is unreadable to the preflight principal") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise CanaryPreflightError(f"{name} must be a regular file")


def _validate_start_wrapper(path: Path) -> None:
    """Accept only the packaged wrapper that executes the WSS-only launcher."""

    _regular_file(path, name="RPM start wrapper")
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CanaryPreflightError("RPM start wrapper is unreadable") from error
    if any(fragment not in content for fragment in _WRAPPER_REQUIRED_FRAGMENTS):
        raise CanaryPreflightError("RPM start wrapper is not the required WSS headless launcher")
    prohibited = ("gateway_http_pull", "--migration-http-pull-fallback", "pc_agent.ws_agent", "helpdesk")
    if any(fragment in content.casefold() for fragment in prohibited):
        raise CanaryPreflightError("RPM start wrapper contains a prohibited fallback or legacy reference")


def validate_service_unit(
    unit_text: str, *, start_wrapper: Path = _START_WRAPPER
) -> dict[str, object]:
    """Parse only the safe subset of the installed unit without Environment dumps."""
    values: dict[str, str] = {}
    for raw_line in unit_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"User", "Group", "Restart", "NoNewPrivileges", "ProtectSystem", "ExecStart"}:
            values[key] = value.strip()
    for key, expected in _REQUIRED_UNIT_VALUES.items():
        if values.get(key, "").casefold() != expected:
            raise CanaryPreflightError(f"service unit requires {key}={expected}")
    exec_start = values.get("ExecStart", "")
    if exec_start == _START_WRAPPER_PATH:
        _validate_start_wrapper(start_wrapper)
    elif any(fragment not in exec_start for fragment in _DIRECT_LAUNCHER_FRAGMENTS):
        raise CanaryPreflightError("service unit is not the required WSS headless launcher")
    prohibited = ("gateway_http_pull", "--migration-http-pull-fallback", "pc_agent.ws_agent", "helpdesk")
    if any(fragment in unit_text.casefold() for fragment in prohibited):
        raise CanaryPreflightError("service unit contains a prohibited fallback or legacy reference")
    return {
        "user": values["User"],
        "group": values["Group"],
        "restart": values["Restart"],
        "no_new_privileges": True,
        "protect_system": "strict",
    }


def validate_release_selector(install_root: Path, expected_source_revision: str) -> dict[str, str]:
    """Prove the immutable selected release matches the approved source revision."""
    if not _REVISION.fullmatch(expected_source_revision):
        raise CanaryPreflightError("expected source revision is invalid")
    selector = install_root / "current.json"
    _regular_file(selector, name="release selector")
    try:
        selection = json.loads(selector.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanaryPreflightError("release selector is not valid JSON") from error
    if not isinstance(selection, dict) or set(selection) != {"schema_version", "version", "source_revision"}:
        raise CanaryPreflightError("release selector schema is invalid")
    if selection.get("schema_version") != 1 or not isinstance(selection.get("version"), str) or not _VERSION.fullmatch(selection["version"]):
        raise CanaryPreflightError("release selector version is invalid")
    source_revision = selection.get("source_revision")
    if not isinstance(source_revision, str) or not _REVISION.fullmatch(source_revision):
        raise CanaryPreflightError("release selector source revision is invalid")
    if source_revision != expected_source_revision:
        raise CanaryPreflightError("release selector source revision does not match expected source revision")
    release = install_root / "versions" / selection["version"]
    if release.is_symlink() or not release.is_dir():
        raise CanaryPreflightError("selected immutable release directory is missing")
    _regular_file(install_root / "launcher", name="selected launcher")
    release_launchers = (
        (release / "launcher", "release launcher"),
        (release / "endpoint-agent" / "endpoint-agent", "packaged release executable"),
    )
    for candidate, name in release_launchers:
        try:
            _regular_file(candidate, name=name)
            break
        except CanaryPreflightError:
            continue
    else:
        raise CanaryPreflightError("selected release executable is missing")
    _regular_file(release / "manifest.json", name="release manifest")
    return {"version": selection["version"], "source_revision": source_revision}


def _run(command: Sequence[str]) -> str:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode:
        raise CanaryPreflightError(f"required read-only command failed: {command[0]}")
    return completed.stdout


def _verify_origin(origin: str, ca_file: Path) -> dict[str, object]:
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise CanaryPreflightError("expected Endpoint origin must be an absolute HTTPS origin")
    _regular_file(ca_file, name="configured CA file")
    port = parsed.port or 443
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)})
    if not addresses:
        raise CanaryPreflightError("Endpoint DNS returned no TCP address")
    context = ssl.create_default_context(cafile=str(ca_file))
    with socket.create_connection((parsed.hostname, port), timeout=10) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=parsed.hostname) as tls_socket:
            tls_socket.getpeercert()
    return {"origin": origin, "dns_addresses": addresses, "strict_tls": "passed"}


def collect_preflight(
    *,
    expected_endpoint_origin: str,
    expected_source_revision: str,
    service_unit: str,
    install_root: Path,
    config_root: Path,
    data_root: Path,
) -> dict[str, object]:
    """Collect only bounded metadata; credential contents are never opened."""
    if service_unit != "endpoint-agent.service":
        raise CanaryPreflightError("only endpoint-agent.service is permitted")
    if _run(("systemctl", "is-active", "--quiet", service_unit)) is not None:
        pass
    _run(("systemctl", "is-enabled", "--quiet", service_unit))
    unit = validate_service_unit(_run(("systemctl", "cat", service_unit)))
    release = validate_release_selector(install_root, expected_source_revision)
    for name in ("device-credential", "enrollment-identity.json"):
        item = data_root / name
        _regular_file(item, name=name)
        if item.stat().st_mode & 0o077:
            raise CanaryPreflightError(f"{name} is readable outside the service account")
    ca_file = config_root / "ca.crt"
    return {
        "schema_version": "endpoint_installed_alt_agent_preflight_v1",
        "service": unit,
        "release": release,
        "local_state": {"data_root": "present", "credential_metadata": "protected"},
        "network": _verify_origin(expected_endpoint_origin, ca_file),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-endpoint-origin", required=True)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--service-unit", default="endpoint-agent.service")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--install-root", type=Path, default=Path("/opt/endpoint-agent"))
    parser.add_argument("--config-root", type=Path, default=Path("/etc/endpoint-agent"))
    parser.add_argument("--data-root", type=Path, default=Path("/var/lib/endpoint-agent"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        payload = collect_preflight(
            expected_endpoint_origin=args.expected_endpoint_origin,
            expected_source_revision=args.expected_source_revision,
            service_unit=args.service_unit,
            install_root=args.install_root,
            config_root=args.config_root,
            data_root=args.data_root,
        )
        write_secure_json(
            args.output,
            payload,
            allowed_keys=frozenset({"schema_version", "service", "release", "local_state", "network"}),
        )
    except CanaryPreflightError as error:
        print(f"preflight failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
