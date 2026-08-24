"""Fail-closed validation of redacted Windows EndpointAgent preflight facts."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from tools.canary.evidence_models import (
    CanaryEvidenceError,
    validate_evidence_payload,
    write_secure_json,
)


class WindowsPreflightError(ValueError):
    """A Windows installed-agent canary invariant was not proven."""


_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "agent",
        "services",
        "runtime",
        "msi",
        "acl",
        "safe_status",
        "network",
        "completion_proof",
    }
)
_INSTALL_ROOT = "c:\\program files\\endpoint platform\\agent\\"


def _mapping(value: object, *, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WindowsPreflightError(f"{name} schema is invalid")
    return value


def _require(value: object, *, name: str, expected: object = True) -> None:
    if value != expected:
        raise WindowsPreflightError(f"{name} is invalid")


def _safe_path(value: object, *, name: str, suffix: str) -> None:
    if not isinstance(value, str) or not value.casefold().startswith(_INSTALL_ROOT):
        raise WindowsPreflightError(f"{name} path is invalid")
    if not value.casefold().endswith(suffix.casefold()):
        raise WindowsPreflightError(f"{name} path is invalid")


def _validate_agent_service(services: Mapping[str, object]) -> None:
    agent = _mapping(services.get("agent"), name="agent service")
    _require(agent.get("name"), name="agent service name", expected="EndpointAgent")
    _require(agent.get("start_mode"), name="agent service start mode", expected="Automatic")
    _require(agent.get("state"), name="agent service state", expected="Running")
    _require(agent.get("account"), name="agent service account", expected="NT AUTHORITY\\LocalService")
    _require(agent.get("pid_present"), name="agent service PID")
    host = _mapping(agent.get("host"), name="agent service host")
    _require(host.get("regular"), name="agent service host regular")
    _require(host.get("reparse"), name="agent service host reparse", expected=False)
    _require(host.get("fixed_entrypoint"), name="agent service entrypoint")
    _safe_path(host.get("path"), name="agent service host", suffix="endpoint-agent-service.exe")
    children = agent.get("runtime_children")
    if not isinstance(children, list) or len(children) != 1:
        raise WindowsPreflightError("agent runtime child is invalid")
    child = _mapping(children[0], name="agent runtime child")
    _require(child.get("regular"), name="agent runtime child regular")
    _require(child.get("reparse"), name="agent runtime child reparse", expected=False)
    _require(child.get("service_child"), name="agent runtime child identity")
    _require(child.get("safe_command"), name="agent runtime child command")
    _safe_path(child.get("path"), name="agent runtime child", suffix="pc_agent.exe")


def _validate_updater(services: Mapping[str, object]) -> None:
    updater = _mapping(services.get("updater"), name="updater service")
    _require(updater.get("name"), name="updater service name", expected="EndpointAgentUpdater")
    _require(updater.get("start_mode"), name="updater start mode", expected="Manual")
    _require(updater.get("state"), name="updater state", expected="Stopped")
    _require(updater.get("account"), name="updater account", expected="LocalSystem")
    _require(updater.get("regular"), name="updater regular")
    _require(updater.get("listener"), name="updater listener", expected=False)
    _require(updater.get("safe_command"), name="updater command")


def _validate_runtime(
    projection: Mapping[str, object], manifest_agent: Mapping[str, object]
) -> None:
    runtime = _mapping(projection.get("runtime"), name="runtime")
    _require(runtime.get("selector_regular"), name="selector regular")
    _require(runtime.get("selector_reparse"), name="selector reparse", expected=False)
    _require(runtime.get("selected_runtime_present"), name="selected runtime")
    _require(runtime.get("http_fallback"), name="HTTP fallback", expected=False)
    _require(runtime.get("helpdesk_reference"), name="Helpdesk reference", expected=False)
    _require(runtime.get("selector_version"), name="selector version", expected=manifest_agent.get("version"))
    _require(
        runtime.get("selector_source_revision"),
        name="selector source revision",
        expected=manifest_agent.get("source_revision"),
    )


def _validate_msi_acl_network(
    projection: Mapping[str, object], manifest_agent: Mapping[str, object]
) -> None:
    msi = _mapping(projection.get("msi"), name="MSI")
    _require(msi.get("version"), name="MSI version", expected=manifest_agent.get("version"))
    _require(msi.get("sha256"), name="MSI SHA-256", expected=manifest_agent.get("package_sha256"))
    _require(msi.get("owned_files"), name="MSI ownership")
    acl = _mapping(projection.get("acl"), name="ACL")
    for key in ("data_root_protected", "required_principals", "protected_file_regular"):
        _require(acl.get(key), name=f"ACL {key}")
    for key in ("ordinary_user_read", "protected_file_reparse"):
        _require(acl.get(key), name=f"ACL {key}", expected=False)
    network = _mapping(projection.get("network"), name="network")
    for key in ("strict_tls", "hostname_valid", "gateway_wss"):
        _require(network.get(key), name=f"network {key}")
    _require(network.get("redirected"), name="network redirect", expected=False)
    _require(network.get("capability"), name="network capability", expected="context.diagnostic.collect")


def validate_preflight(
    projection: Mapping[str, object], manifest: Mapping[str, object]
) -> dict[str, object]:
    """Validate only a bounded, redacted Windows preflight projection."""
    if set(projection) != _TOP_LEVEL_KEYS:
        raise WindowsPreflightError("projection schema is invalid")
    if projection.get("schema_version") != "windows_agent_preflight_v1":
        raise WindowsPreflightError("projection schema is invalid")
    agent = _mapping(projection["agent"], name="agent")
    manifest_agent = _mapping(manifest.get("agent"), name="manifest agent")
    if agent.get("platform") != "windows_amd64":
        raise WindowsPreflightError("agent platform is invalid")
    if manifest_agent.get("platform") != "windows_amd64":
        raise WindowsPreflightError("manifest platform is invalid")
    try:
        validate_evidence_payload(projection, allowed_keys=_TOP_LEVEL_KEYS)
    except CanaryEvidenceError as error:
        raise WindowsPreflightError("projection contains forbidden evidence") from error
    services = _mapping(projection.get("services"), name="services")
    _validate_agent_service(services)
    _validate_updater(services)
    _validate_runtime(projection, manifest_agent)
    _validate_msi_acl_network(projection, manifest_agent)
    return {"status": "READY", "platform": "windows_amd64"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projection", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        projection = json.loads(args.projection.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = validate_preflight(
            _mapping(projection, name="projection"), _mapping(manifest, name="manifest")
        )
        write_secure_json(args.output, result, allowed_keys=frozenset(result))
    except (OSError, json.JSONDecodeError, WindowsPreflightError) as error:
        print(f"windows preflight failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
