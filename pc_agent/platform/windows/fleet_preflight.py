"""Bounded read-only eligibility for canonical Setup.

This local snapshot authorizes no mutation and proves no live authentication.
Setup still performs its authoritative, locked admission before installation.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import ssl
from urllib.parse import urlsplit

from endpoint_contracts.runtime_payload import read_json, version_tuple
from . import installation_provenance as provenance, installer_fence, msi_inventory
from .disk_readiness import _existing_directory
from .update_paths import WindowsUpdatePaths
from .update_transaction import active_update_state

MAX_PREFLIGHT_BYTES = 16384
SCHEMA = "endpoint_windows_fleet_preflight_v1"
SERVICES = ("EndpointAgent", "EndpointAgentUpdater")


def _foundation(paths: WindowsUpdatePaths) -> dict:
    """Use the native Task7 inventory, never a package receipt alone."""
    state = installer_fence.state_root(paths)
    modern = state / "foundation.json"
    if provenance._present(modern):
        installer_fence.assert_state_security(modern)
        authority = read_json(provenance._read(modern, 4096), 4096)
        if (
            set(authority) != {"schema_version", "release"}
            or type(authority["schema_version"]) is not int
            or authority["schema_version"] != 1
            or not isinstance(authority["release"], dict)
        ):
            raise provenance.ProvenanceConflict()
        release = authority["release"]
        digest = release.get("package_sha256")
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            raise provenance.ProvenanceConflict()
        package_path = state / "packages" / digest / "EndpointAgent.msi"
        installer_fence.assert_state_security(package_path)
        expected = msi_inventory.read_expected_package(package_path, release)
        package = expected.package
        feature = msi_inventory.verify_foundation(
            package, paths.install_root, expected=expected
        )
    else:
        cache = paths.updates_root.parent / "installer-cache"
        receipt = read_json(
            provenance._read(cache / "installer-provenance.json", 4096), 4096
        )
        from .runtime_identity import _LEGACY_MSI_CONTRACTS

        contract = _LEGACY_MSI_CONTRACTS.get(receipt.get("package_sha256"))
        if (
            set(receipt)
            != {
                "cache_file",
                "initial_runtime_tree_sha256",
                "package_sha256",
                "product_code",
                "release_manifest_schema_version",
                "schema_version",
                "source_revision",
                "version",
            }
            or contract is None
            or receipt["schema_version"] != "endpoint_windows_installer_provenance_v1"
            or receipt["release_manifest_schema_version"]
            != "endpoint_windows_release_v1"
            or receipt["version"] != contract["version"]
            or receipt["source_revision"] != contract["source_revision"]
            or receipt["initial_runtime_tree_sha256"] != contract["tree_sha256"]
            or receipt["cache_file"]
            != f"msi-{receipt['package_sha256']}/EndpointAgent.msi"
        ):
            raise provenance.ProvenanceConflict()
        package = msi_inventory.read_package(
            cache / receipt["cache_file"], receipt["package_sha256"]
        )
        if (
            package.product_code != receipt["product_code"]
            or package.version != contract["version"]
        ):
            raise provenance.ProvenanceConflict()
        feature = msi_inventory.verify_foundation(package, paths.install_root)
        release = receipt
    version_tuple(package.version)
    source = release["source_revision"]
    if not isinstance(source, str) or not re.fullmatch("[0-9a-f]{40}", source):
        raise provenance.ProvenanceConflict()
    return {
        "version": package.version,
        "source_revision": source,
        "package_sha256": package.sha256,
        "product_code": package.product_code,
        "native_verified": True,
        "feature_state": feature,
    }


def _services(paths: WindowsUpdatePaths) -> dict:
    if os.name != "nt":
        return {
            name: {
                "present": None,
                "state": None,
                "start_mode": None,
                "identity_valid": None,
            }
            for name in SERVICES
        }
    import win32service
    import pywintypes

    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    result = {}
    try:
        for name, filename, account, argument in (
            (
                "EndpointAgent",
                "endpoint-agent-service.exe",
                "NT AUTHORITY\\LocalService",
                "--agent-service",
            ),
            (
                "EndpointAgentUpdater",
                "endpoint-agent-updater.exe",
                "LocalSystem",
                "--updater-service",
            ),
        ):
            handle = None
            try:
                handle = win32service.OpenService(
                    manager,
                    name,
                    win32service.SERVICE_QUERY_CONFIG
                    | win32service.SERVICE_QUERY_STATUS,
                )
                config = win32service.QueryServiceConfig(handle)
                status = win32service.QueryServiceStatus(handle)
                # Fixed service executable only; arguments and inherited shell
                # commands are never echoed and do not establish safe identity.
                command = config[3].strip()
                expected = str(paths.install_root / filename)
                identity = (
                    command.casefold() in {f'"{expected}" {argument}'.casefold()}
                    and config[7].casefold() == account.casefold()
                )
                if identity:
                    provenance._read(paths.install_root / filename, 64 * 1024 * 1024)
                result[name] = {
                    "present": True,
                    "state": {1: "stopped", 4: "running"}.get(
                        status[1], "transitioning"
                    ),
                    "start_mode": {2: "automatic", 3: "manual", 4: "disabled"}.get(
                        config[1], "invalid"
                    ),
                    "identity_valid": identity,
                }
            except (OSError, ValueError, pywintypes.error) as error:
                missing = getattr(error, "winerror", None) == 1060
                result[name] = {
                    "present": False if missing else None,
                    "state": None,
                    "start_mode": None,
                    "identity_valid": False if missing else None,
                }
            finally:
                if handle is not None:
                    win32service.CloseServiceHandle(handle)
    finally:
        win32service.CloseServiceHandle(manager)
    return result


def _shape(paths: WindowsUpdatePaths) -> dict:
    from pc_agent.enrollment_identity import canonical_enrollment_device_id

    root = paths.updates_root.parent
    credential = root / "device-credential"
    present = provenance._present(credential)
    valid = False
    identity_valid = False
    try:
        from .acl import PyWin32AclAdapter

        PyWin32AclAdapter().assert_protected_file(credential)
        raw = provenance._read(credential, 45)
        valid = re.fullmatch(rb"[A-Za-z0-9_-]{43}(?:\r?\n)?", raw) is not None
        record = read_json(
            provenance._read(root / "enrollment-identity.json", 160), 160
        )
        if (
            set(record) == {"schema_version", "device_id"}
            and record["schema_version"] == "endpoint_enrollment_identity_v1"
        ):
            canonical_enrollment_device_id(record["device_id"])
            identity_valid = True
    except Exception:
        pass
    return {
        "present": present,
        "shape_valid": valid,
        "enrollment_shape_valid": identity_valid,
        "authenticated": None,
    }


def _ca_parseable(raw: bytes) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=raw.decode("ascii"))
    return bool(context.cert_store_stats()["x509_ca"])


def _ca(paths: WindowsUpdatePaths) -> dict:
    path = paths.updates_root.parent / "endpoint-ca.crt"
    present = provenance._present(path)
    parseable = False
    try:
        parseable = _ca_parseable(provenance._read(path, 65536))
    except Exception:
        pass
    return {"present": present, "parseable": parseable, "strict_live_tls": None}


def _disk(paths: WindowsUpdatePaths, setup_package=None) -> dict:
    # Only the embedded package's native costing can establish Setup capacity.
    # This preliminary fact detects a full volume without inventing a payload.
    free = min(
        shutil.disk_usage(_existing_directory(path)).free
        for path in (paths.install_root, paths.updates_root.parent)
    )
    result = {
        "sufficient": None,
        "scope": "setup_allocation_unknown",
        "free_bytes": free,
    }
    if setup_package is not None:
        from .setup_entry import _setup_disk_allocations
        from .disk_readiness import require_allocation_space, DiskInsufficient

        try:
            allocations = _setup_disk_allocations(setup_package, paths)
            require_allocation_space(allocations)
        except DiskInsufficient:
            result.update(sufficient=False, scope="verified_allocations")
        except Exception:
            pass
        else:
            result.update(sufficient=True, scope="verified_allocations")
    return result


def _origin(paths: WindowsUpdatePaths) -> dict:
    path = paths.updates_root.parent / "endpoint-origin"
    present = provenance._present(path)
    valid = None if not present else False
    if present:
        try:
            origin = provenance._read(path, 2048).decode("utf-8").strip()
            value = urlsplit(origin)
            valid = (
                value.scheme == "https"
                and bool(value.hostname)
                and value.username is None
                and value.password is None
                and value.path in ("", "/")
                and not value.query
                and not value.fragment
                and (value.port is None or 1 <= value.port <= 65535)
            )
        except Exception:
            pass
    result = {
        "present": present,
        "https_shape_valid": valid,
        "scope": "protected_override" if present else "compiled_default",
    }
    return result


def _wss(paths: WindowsUpdatePaths) -> dict:
    result = {
        "status_present": provenance._present(
            paths.updates_root.parent / "canary-status.json"
        ),
        "historical_proof": None,
        "live_connected": None,
        "scope": "historical_status_only",
    }
    try:
        from .canary_status import _validated_status

        status = _validated_status(
            read_json(
                provenance._read(
                    paths.updates_root.parent / "canary-status.json", 16384
                ),
                16384,
            )
        )
        transport = status["transport"]
        result["historical_proof"] = (
            transport["gateway_wss"] is True
            and transport["strict_tls"] is True
            and transport["hostname_valid"] is True
            and transport["redirected"] is False
            and transport["http_fallback"] is False
        )
    except Exception:
        pass
    return result


def collect_fleet_preflight(
    paths: WindowsUpdatePaths, target_version: str, *, setup_package=None
) -> dict[str, object]:
    """Return only fixed, redacted facts; never enroll, repair, lock or publish."""
    version_tuple(target_version)
    target_package_hash = None
    if setup_package is not None:
        from .setup_entry import _verify_embedded_msi

        release_path, _wrapper = _verify_embedded_msi(setup_package)
        target_release = read_json(release_path.read_bytes(), 4096)
        if target_release["version"] != target_version:
            raise ValueError("PREFLIGHT_TARGET_INVALID")
        target_package_hash = target_release["package_sha256"]
    pending = {"active_or_degraded": False, "state": None, "installer_phase": None}
    try:
        fence = installer_fence.read_fence(paths)
        if fence is not None:
            pending.update(
                active_or_degraded=True,
                state="installer-recovery-required",
                installer_phase=fence["phase"],
            )
        state = active_update_state(paths)
        if state is not None:
            pending.update(active_or_degraded=True, state=state)
    except Exception:
        pending.update(active_or_degraded=True, state="state-invalid")
    foundation = {
        "version": None,
        "source_revision": None,
        "package_sha256": None,
        "product_code": None,
        "native_verified": False,
        "feature_state": None,
    }
    try:
        foundation = _foundation(paths)
    except Exception:
        pass  # Native MSI/ACL errors also mean unknown authority.
    core = {
        "version": None,
        "source_revision": None,
        "minimum_launcher_version": None,
        "origin": None,
        "verified": False,
        "package_sha256": None,
        "package_size": None,
        "compatibility_scope": None,
    }
    conflict = False
    try:
        resulting = target_version
        if foundation["version"] is not None and version_tuple(
            foundation["version"]
        ) > version_tuple(target_version):
            resulting = foundation["version"]
        selected = provenance.inspect_installed_core(
            paths, resulting_foundation=resulting
        ).current
        if selected is not None:
            identity = selected.identity
            receipt = read_json(selected.receipt_bytes, 4096)
            owner = (
                read_json(selected.owner_bytes, 16 * 1024 * 1024)
                if selected.origin == "retained_msi"
                else None
            )
            package_hash = (
                receipt["sha256"]
                if selected.origin == "zip"
                else owner["package"]["sha256"]
                if owner
                else receipt.get(
                    "package_sha256", receipt.get("release", {}).get("package_sha256")
                )
            )
            core.update(
                version=identity.version,
                source_revision=identity.source_revision,
                minimum_launcher_version=identity.minimum_launcher_version,
                origin=selected.origin,
                verified=True,
                package_sha256=package_hash,
                package_size=receipt.get("size") if selected.origin == "zip" else None,
                compatibility_scope="immutable_legacy_identity"
                if selected.compatibility_foundations
                else "payload_contract",
            )
    except Exception:
        conflict = True
    if (
        target_package_hash is not None
        and foundation["native_verified"]
        and foundation["version"] == target_version
        and foundation["package_sha256"] != target_package_hash
    ):
        conflict = True
    try:
        services = _services(paths)
    except Exception:
        services = {
            name: {
                "present": None,
                "state": None,
                "start_mode": None,
                "identity_valid": None,
            }
            for name in SERVICES
        }
    credential, ca, origin = _shape(paths), _ca(paths), _origin(paths)
    from .setup_entry import _setup_msi_required

    no_transition = (
        core["verified"]
        and foundation["native_verified"]
        and not _setup_msi_required(
            target_version,
            foundation["version"],
            installation_valid=True,
            msi_path=setup_package,
            paths=paths,
        )
    )
    try:
        disk = _disk(
            paths,
            None
            if no_transition or pending["active_or_degraded"] or conflict
            else setup_package,
        )
    except (OSError, ValueError):
        disk = {
            "sufficient": None,
            "scope": "setup_allocation_unknown",
            "free_bytes": None,
        }
    if pending["active_or_degraded"]:
        eligibility = "UPDATE_IN_PROGRESS"
    elif conflict:
        eligibility = "PROVENANCE_CONFLICT"
    elif not foundation["native_verified"]:
        eligibility = "FOUNDATION_UNKNOWN"
    elif disk["sufficient"] is False:
        eligibility = "DISK_INSUFFICIENT"
    elif any(
        fact["identity_valid"] is not True
        or fact["start_mode"] not in ("automatic", "manual")
        for fact in services.values()
    ):
        eligibility = "SERVICE_INVALID"
    elif not credential["shape_valid"] or not credential["enrollment_shape_valid"]:
        eligibility = "CREDENTIAL_REPAIR_REQUIRED"
    elif not ca["parseable"] or origin["https_shape_valid"] is False:
        eligibility = "TLS_REPAIR_REQUIRED"
    elif no_transition:
        eligibility = "ALREADY_CURRENT"
    elif disk["sufficient"] is not True:
        eligibility = "DISK_UNKNOWN"
    else:
        eligibility = "READY_FOR_SETUP_UPGRADE"
    result = {
        "schema_version": SCHEMA,
        "target_version": target_version,
        "eligibility": eligibility,
        "snapshot_scope": "local_non_atomic_read_only",
        "core": core,
        "foundation": foundation,
        "msi": {
            "product_code": foundation["product_code"],
            "version": foundation["version"],
            "native_verified": foundation["native_verified"],
        },
        "origin": origin,
        "wss": _wss(paths),
        "update_lane": {
            "commands": "wss",
            "updates": "https",
            "migration_http_pull_fallback": False,
            "live_owner": None,
        },
        "pending": pending,
        "provenance": {
            "conflict": conflict,
            "verified": core["verified"] and foundation["native_verified"],
        },
        "credential": credential,
        "ca": ca,
        "disk": disk,
        "services": services,
    }
    if len(json.dumps(result, separators=(",", ":")).encode()) > MAX_PREFLIGHT_BYTES:
        raise ValueError("PREFLIGHT_BOUND_EXCEEDED")
    return result
