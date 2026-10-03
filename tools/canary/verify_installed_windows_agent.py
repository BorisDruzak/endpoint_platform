"""Fail-closed validation of redacted Windows EndpointAgent preflight facts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from tools.canary.evidence_models import (
    CanaryEvidenceError,
    validate_evidence_payload,
    write_secure_json,
)


class WindowsPreflightError(ValueError):
    """A Windows installed-agent canary invariant was not proven."""


@dataclass(frozen=True, slots=True)
class CompletionExpectation:
    """The one command whose terminal result may satisfy post-operation proof."""

    command_id: str
    capability: str = "context.diagnostic.collect"

    def __post_init__(self) -> None:
        if not isinstance(self.command_id, str) or not self.command_id:
            raise ValueError("completion command id is invalid")
        if self.capability != "context.diagnostic.collect":
            raise ValueError("completion capability is invalid")


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
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_PRODUCT_CODE = re.compile(r"\{[0-9A-Fa-f-]{36}\}\Z")


def _mapping(value: object, *, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WindowsPreflightError(f"{name} schema is invalid")
    return value


def _require(value: object, *, name: str, expected: object = True) -> None:
    if value != expected or (isinstance(expected, bool) and type(value) is not bool):
        raise WindowsPreflightError(f"{name} is invalid")


def _manifest_identity(value: object, *, name: str) -> Mapping[str, object]:
    identity = _mapping(value, name=name)
    if (
        set(identity) != {"platform", "version", "source_revision", "package_sha256"}
        or identity.get("platform") != "windows_amd64"
        or not isinstance(identity.get("version"), str)
        or not _VERSION.fullmatch(identity["version"])
        or not isinstance(identity.get("source_revision"), str)
        or not _REVISION.fullmatch(identity["source_revision"])
        or not isinstance(identity.get("package_sha256"), str)
        or not _SHA256.fullmatch(identity["package_sha256"])
    ):
        raise WindowsPreflightError(f"{name} is invalid")
    return identity


def _safe_path(value: object, *, name: str, suffix: str) -> None:
    if not isinstance(value, str) or not value.casefold().startswith(_INSTALL_ROOT):
        raise WindowsPreflightError(f"{name} path is invalid")
    if not value.casefold().endswith(suffix.casefold()):
        raise WindowsPreflightError(f"{name} path is invalid")


def _validate_agent_service(services: Mapping[str, object]) -> None:
    agent = _mapping(services.get("agent"), name="agent service")
    _require(agent.get("name"), name="agent service name", expected="EndpointAgent")
    _require(
        agent.get("start_mode"), name="agent service start mode", expected="Automatic"
    )
    _require(agent.get("state"), name="agent service state", expected="Running")
    _require(
        agent.get("account"),
        name="agent service account",
        expected="NT AUTHORITY\\LocalService",
    )
    _require(agent.get("pid_present"), name="agent service PID")
    host = _mapping(agent.get("host"), name="agent service host")
    _require(host.get("regular"), name="agent service host regular")
    _require(host.get("reparse"), name="agent service host reparse", expected=False)
    _require(host.get("fixed_entrypoint"), name="agent service entrypoint")
    _safe_path(
        host.get("path"), name="agent service host", suffix="endpoint-agent-service.exe"
    )
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
    _require(
        updater.get("name"),
        name="updater service name",
        expected="EndpointAgentUpdater",
    )
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
    origin = runtime.get("origin")
    common_keys = {
        "origin",
        "selector_regular",
        "selector_reparse",
        "selector_version",
        "selector_source_revision",
        "selected_runtime_present",
        "http_fallback",
        "helpdesk_reference",
    }
    zip_keys = {
        "bundle_sha256",
        "bundle_size",
        "bundle_manifest_verified",
        "bundle_receipt_verified",
        "bundle_acl_protected",
    }
    if origin not in ("msi", "zip", "retained_msi") or set(runtime) != (
        common_keys | (zip_keys if origin == "zip" else set())
    ):
        raise WindowsPreflightError("runtime schema is invalid")
    _require(runtime.get("selector_regular"), name="selector regular")
    _require(runtime.get("selector_reparse"), name="selector reparse", expected=False)
    _require(runtime.get("selected_runtime_present"), name="selected runtime")
    _require(runtime.get("http_fallback"), name="HTTP fallback", expected=False)
    _require(
        runtime.get("helpdesk_reference"), name="Helpdesk reference", expected=False
    )
    _require(
        runtime.get("selector_version"),
        name="selector version",
        expected=manifest_agent.get("version"),
    )
    _require(
        runtime.get("selector_source_revision"),
        name="selector source revision",
        expected=manifest_agent.get("source_revision"),
    )
    agent = _mapping(projection.get("agent"), name="agent")
    _require(
        agent.get("version"), name="agent version", expected=manifest_agent["version"]
    )
    _require(
        agent.get("source_revision"),
        name="agent source revision",
        expected=manifest_agent["source_revision"],
    )
    if origin == "zip":
        _require(
            runtime.get("bundle_sha256"),
            name="ZIP SHA-256",
            expected=manifest_agent["package_sha256"],
        )
        if type(runtime.get("bundle_size")) is not int or runtime["bundle_size"] <= 0:
            raise WindowsPreflightError("ZIP size is invalid")
        for key in (
            "bundle_manifest_verified",
            "bundle_receipt_verified",
            "bundle_acl_protected",
        ):
            _require(runtime.get(key), name=f"ZIP {key}")


def _validate_msi_acl_network(
    projection: Mapping[str, object],
    manifest_agent: Mapping[str, object],
    manifest_installer: Mapping[str, object],
) -> None:
    msi = _mapping(projection.get("msi"), name="MSI")
    if set(msi) != {
        "version",
        "source_revision",
        "sha256",
        "product_code",
        "owned_files",
    }:
        raise WindowsPreflightError("MSI schema is invalid")
    _require(
        msi.get("version"), name="MSI version", expected=manifest_installer["version"]
    )
    _require(
        msi.get("source_revision"),
        name="MSI source revision",
        expected=manifest_installer["source_revision"],
    )
    _require(
        msi.get("sha256"),
        name="MSI SHA-256",
        expected=manifest_installer["package_sha256"],
    )
    if not isinstance(msi.get("product_code"), str) or not _PRODUCT_CODE.fullmatch(
        msi["product_code"]
    ):
        raise WindowsPreflightError("MSI product code is invalid")
    _require(msi.get("owned_files"), name="MSI ownership")
    if (
        _mapping(projection.get("runtime"), name="runtime").get("origin") == "msi"
        and manifest_agent != manifest_installer
        and "fleet_preflight" not in projection
    ):
        raise WindowsPreflightError("MSI-selected runtime identity is invalid")
    acl = _mapping(projection.get("acl"), name="ACL")
    for key in (
        "data_root_protected",
        "required_principals",
        "protected_file_regular",
        "status_artifact_protected",
        "provenance_artifact_protected",
        "msi_artifact_protected",
    ):
        _require(acl.get(key), name=f"ACL {key}")
    for key in ("ordinary_user_read", "protected_file_reparse"):
        _require(acl.get(key), name=f"ACL {key}", expected=False)
    safe_status = _mapping(projection.get("safe_status"), name="safe status")
    if set(safe_status) != {
        "service",
        "identity_present",
        "regular",
        "reparse",
        "release_version",
        "release_source_revision",
    }:
        raise WindowsPreflightError("safe status schema is invalid")
    _require(safe_status.get("service"), name="safe status service", expected="running")
    _require(safe_status.get("identity_present"), name="safe status identity")
    _require(safe_status.get("regular"), name="safe status regular")
    _require(safe_status.get("reparse"), name="safe status reparse", expected=False)
    _require(
        safe_status.get("release_version"),
        name="safe status version",
        expected=manifest_agent.get("version"),
    )
    _require(
        safe_status.get("release_source_revision"),
        name="safe status source revision",
        expected=manifest_agent.get("source_revision"),
    )
    network = _mapping(projection.get("network"), name="network")
    if set(network) != {
        "strict_tls",
        "hostname_valid",
        "redirected",
        "gateway_wss",
        "http_fallback",
        "capability",
    }:
        raise WindowsPreflightError("network schema is invalid")
    for key in ("strict_tls", "hostname_valid", "gateway_wss"):
        _require(network.get(key), name=f"network {key}")
    _require(network.get("redirected"), name="network redirect", expected=False)
    _require(network.get("http_fallback"), name="network HTTP fallback", expected=False)
    _require(
        network.get("capability"),
        name="network capability",
        expected="context.diagnostic.collect",
    )


def _validate_fleet_facts(
    value: object,
    manifest_agent: Mapping,
    manifest_installer: Mapping,
    runtime_origin: object,
) -> None:
    """Exact primitive schema permits only credential shape, never a bearer.

    This supplements installed checks; eligibility alone cannot yield READY.
    """
    from endpoint_contracts.runtime_payload import version_tuple

    facts = _mapping(value, name="fleet preflight")
    fields = {
        "core": {
            "version",
            "source_revision",
            "minimum_launcher_version",
            "origin",
            "verified",
            "package_sha256",
            "package_size",
            "compatibility_scope",
        },
        "foundation": {
            "version",
            "source_revision",
            "package_sha256",
            "product_code",
            "native_verified",
            "feature_state",
        },
        "msi": {"version", "product_code", "native_verified"},
        "origin": {"present", "https_shape_valid", "scope"},
        "wss": {"status_present", "historical_proof", "live_connected", "scope"},
        "update_lane": {
            "commands",
            "updates",
            "migration_http_pull_fallback",
            "live_owner",
        },
        "pending": {"active_or_degraded", "state", "installer_phase"},
        "provenance": {"conflict", "verified"},
        "credential": {
            "present",
            "shape_valid",
            "enrollment_shape_valid",
            "authenticated",
        },
        "ca": {"present", "parseable", "strict_live_tls"},
        "disk": {"sufficient", "scope", "free_bytes"},
        "services": {"EndpointAgent", "EndpointAgentUpdater"},
    }
    if set(facts) != set(fields) | {
        "schema_version",
        "target_version",
        "eligibility",
        "snapshot_scope",
    }:
        raise WindowsPreflightError("fleet preflight schema is invalid")
    if len(json.dumps(facts, separators=(",", ":")).encode()) > 16384:
        raise WindowsPreflightError("fleet preflight exceeds bound")
    _require(
        facts["schema_version"],
        name="fleet schema",
        expected="endpoint_windows_fleet_preflight_v1",
    )
    _require(
        facts["snapshot_scope"],
        name="fleet scope",
        expected="local_non_atomic_read_only",
    )
    try:
        version_tuple(facts["target_version"])
    except (ValueError, TypeError):
        raise WindowsPreflightError("fleet target is invalid") from None
    if not isinstance(facts["eligibility"], str) or facts["eligibility"] not in {
        "ALREADY_CURRENT",
        "READY_FOR_SETUP_UPGRADE",
    }:
        raise WindowsPreflightError("fleet eligibility is degraded")
    groups = {}
    for name, keys in fields.items():
        group = groups[name] = _mapping(facts[name], name=name)
        if set(group) != keys:
            raise WindowsPreflightError("fleet fact schema is invalid")
    for group, keys in {
        "foundation": ("feature_state",),
        "core": ("compatibility_scope",),
        "origin": ("scope",),
        "wss": ("scope",),
        "disk": ("scope",),
    }.items():
        if any(not isinstance(groups[group][key], str) for key in keys):
            raise WindowsPreflightError("fleet string fact is invalid")
    for group, keys in {
        "core": ("verified",),
        "foundation": ("native_verified",),
        "msi": ("native_verified",),
        "pending": ("active_or_degraded",),
        "provenance": ("verified", "conflict"),
        "credential": ("present", "shape_valid", "enrollment_shape_valid"),
        "ca": ("present", "parseable"),
        "update_lane": ("migration_http_pull_fallback",),
    }.items():
        if any(type(groups[group][key]) is not bool for key in keys):
            raise WindowsPreflightError("fleet boolean fact is invalid")
    core, foundation = groups["core"], groups["foundation"]
    for group, expected in ((core, manifest_agent), (foundation, manifest_installer)):
        for key in ("version", "source_revision", "package_sha256"):
            _require(group[key], name="fleet identity", expected=expected[key])
    _require(core["origin"], name="fleet core origin", expected=runtime_origin)
    _require(core["verified"], name="fleet core ownership")
    _require(foundation["native_verified"], name="fleet foundation ownership")
    if foundation["feature_state"] not in {"complete", "foundation_only"}:
        raise WindowsPreflightError("fleet foundation feature is invalid")
    if not isinstance(foundation["product_code"], str) or not _PRODUCT_CODE.fullmatch(
        foundation["product_code"]
    ):
        raise WindowsPreflightError("fleet native product is invalid")
    if groups["msi"] != {
        "version": foundation["version"],
        "product_code": foundation["product_code"],
        "native_verified": True,
    }:
        raise WindowsPreflightError("fleet MSI identity is invalid")
    if core["compatibility_scope"] not in {
        "payload_contract",
        "immutable_legacy_identity",
    }:
        raise WindowsPreflightError("fleet compatibility is invalid")
    floor = core["minimum_launcher_version"]
    try:
        if floor is not None and version_tuple(floor) > version_tuple(
            foundation["version"]
        ):
            raise WindowsPreflightError("fleet foundation is below core requirement")
    except (ValueError, TypeError):
        raise WindowsPreflightError("fleet compatibility is invalid") from None
    if runtime_origin == "zip":
        if (
            type(core["package_size"]) is not int
            or not 0 < core["package_size"] <= 512 * 1024 * 1024
        ):
            raise WindowsPreflightError("fleet ZIP size is invalid")
    elif core["package_size"] is not None:
        raise WindowsPreflightError("fleet core size schema is invalid")
    if groups["pending"] != {
        "active_or_degraded": False,
        "state": None,
        "installer_phase": None,
    }:
        raise WindowsPreflightError("fleet update or installer recovery is active")
    if groups["provenance"] != {"verified": True, "conflict": False}:
        raise WindowsPreflightError("fleet provenance is invalid")
    for key in ("present", "shape_valid", "enrollment_shape_valid"):
        _require(groups["credential"][key], name="fleet credential shape")
    _require(
        groups["credential"]["authenticated"],
        name="fleet authentication scope",
        expected=None,
    )
    for key in ("present", "parseable"):
        _require(groups["ca"][key], name="fleet CA fact")
    _require(groups["ca"]["strict_live_tls"], name="fleet TLS scope", expected=None)
    if groups["update_lane"] != {
        "commands": "wss",
        "updates": "https",
        "migration_http_pull_fallback": False,
        "live_owner": None,
    }:
        raise WindowsPreflightError("fleet update lane is invalid")
    _require(groups["wss"]["live_connected"], name="fleet WSS scope", expected=None)
    _require(
        groups["wss"]["scope"],
        name="fleet WSS scope",
        expected="historical_status_only",
    )
    for key in ("status_present", "historical_proof"):
        if groups["wss"][key] is not None and type(groups["wss"][key]) is not bool:
            raise WindowsPreflightError("fleet WSS fact is invalid")
    origin = groups["origin"]
    if (
        type(origin["present"]) is not bool
        or origin["scope"] not in {"compiled_default", "protected_override"}
        or (
            origin["https_shape_valid"] is not None
            and type(origin["https_shape_valid"]) is not bool
        )
        or origin["https_shape_valid"] is False
    ):
        raise WindowsPreflightError("fleet origin is invalid")
    disk = groups["disk"]
    if (
        disk["sufficient"] is not None
        and type(disk["sufficient"]) is not bool
        or disk["scope"] not in {"verified_allocations", "setup_allocation_unknown"}
        or disk["free_bytes"] is not None
        and (type(disk["free_bytes"]) is not int or not 0 <= disk["free_bytes"] < 2**64)
    ):
        raise WindowsPreflightError("fleet disk fact is invalid")
    for name in fields["services"]:
        service = _mapping(groups["services"][name], name="fleet service")
        if (
            set(service) != {"present", "state", "start_mode", "identity_valid"}
            or service["present"] is not True
            or service["identity_valid"] is not True
            or not isinstance(service["state"], str)
            or not isinstance(service["start_mode"], str)
            or service["state"] not in {"running", "stopped", "transitioning"}
            or service["start_mode"] not in {"automatic", "manual"}
        ):
            raise WindowsPreflightError("fleet service configuration is invalid")


def _validate_completion(
    value: object, expectation: CompletionExpectation | None
) -> None:
    if value is None:
        if expectation is not None:
            raise WindowsPreflightError("completion proof is missing")
        return
    completion = _mapping(value, name="completion proof")
    if set(completion) != {
        "command_id",
        "capability",
        "status",
        "duration_ms",
        "result_item_count",
        "timestamp",
    }:
        raise WindowsPreflightError("completion proof schema is invalid")
    for key in ("command_id", "capability", "status", "timestamp"):
        if not isinstance(completion.get(key), str) or not completion[key]:
            raise WindowsPreflightError("completion proof identity is invalid")
    for key in ("duration_ms", "result_item_count"):
        if (
            not isinstance(completion.get(key), int)
            or isinstance(completion[key], bool)
            or completion[key] < 0
        ):
            raise WindowsPreflightError("completion proof counts are invalid")
    _require(
        completion.get("capability"),
        name="completion capability",
        expected="context.diagnostic.collect",
    )
    if expectation is not None:
        _require(
            completion.get("command_id"),
            name="completion command id",
            expected=expectation.command_id,
        )
        _require(
            completion.get("status"), name="completion status", expected="succeeded"
        )


def validate_preflight(
    projection: Mapping[str, object],
    manifest: Mapping[str, object],
    *,
    require_completion: CompletionExpectation | None = None,
) -> dict[str, object]:
    """Validate only a bounded, redacted Windows preflight projection."""
    if set(projection) not in (_TOP_LEVEL_KEYS, _TOP_LEVEL_KEYS | {"fleet_preflight"}):
        raise WindowsPreflightError("projection schema is invalid")
    if projection.get("schema_version") != "windows_agent_preflight_v1":
        raise WindowsPreflightError("projection schema is invalid")
    agent = _mapping(projection["agent"], name="agent")
    manifest_agent = _manifest_identity(manifest.get("agent"), name="manifest agent")
    origin = _mapping(projection.get("runtime"), name="runtime").get("origin")
    if "installer" in manifest:
        if set(manifest) != {"agent", "installer"}:
            raise WindowsPreflightError("manifest schema is invalid")
        manifest_installer = _manifest_identity(
            manifest["installer"], name="manifest installer"
        )
    elif set(manifest) == {"agent"} and origin == "msi":
        manifest_installer = manifest_agent
    else:
        raise WindowsPreflightError("manifest installer is missing")
    if agent.get("platform") != "windows_amd64":
        raise WindowsPreflightError("agent platform is invalid")
    if manifest_agent.get("platform") != "windows_amd64":
        raise WindowsPreflightError("manifest platform is invalid")
    if "fleet_preflight" in projection:
        _validate_fleet_facts(
            projection["fleet_preflight"], manifest_agent, manifest_installer, origin
        )
        if (
            _mapping(
                projection["fleet_preflight"]["foundation"], name="fleet foundation"
            )["product_code"]
            != _mapping(projection["msi"], name="MSI")["product_code"]
        ):
            raise WindowsPreflightError("fleet and installed MSI identity disagree")
    elif origin == "retained_msi":
        raise WindowsPreflightError("retained ownership requires canonical fleet facts")
    try:
        # Fleet credential container is admitted only through the exact boolean
        # schema above. The generic secret-key guard remains unchanged.
        validate_evidence_payload(
            {
                key: value
                for key, value in projection.items()
                if key != "fleet_preflight"
            },
            allowed_keys=_TOP_LEVEL_KEYS,
        )
    except CanaryEvidenceError as error:
        raise WindowsPreflightError("projection contains forbidden evidence") from error
    services = _mapping(projection.get("services"), name="services")
    _validate_agent_service(services)
    _validate_updater(services)
    _validate_runtime(projection, manifest_agent)
    _validate_msi_acl_network(projection, manifest_agent, manifest_installer)
    _validate_completion(projection.get("completion_proof"), require_completion)
    return {"status": "READY", "platform": "windows_amd64"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projection", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-completion-command-id")
    parser.add_argument("--require-completion-capability")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if bool(args.require_completion_command_id) != bool(
            args.require_completion_capability
        ):
            raise WindowsPreflightError(
                "completion requirement arguments are incomplete"
            )
        expectation = None
        if args.require_completion_command_id:
            expectation = CompletionExpectation(
                command_id=args.require_completion_command_id,
                capability=args.require_completion_capability,
            )
        projection = json.loads(args.projection.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = validate_preflight(
            _mapping(projection, name="projection"),
            _mapping(manifest, name="manifest"),
            require_completion=expectation,
        )
        write_secure_json(args.output, result, allowed_keys=frozenset(result))
    except (OSError, ValueError, json.JSONDecodeError, WindowsPreflightError) as error:
        print(f"windows preflight failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
