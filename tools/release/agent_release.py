"""Inspect release pointers and reserve Windows or ALT build versions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any
from uuid import UUID

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.release import agent_reservations


CATALOG = "docs/releases/current-agent-release.json"
AGENT_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
PACKAGE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9][a-zA-Z0-9.+~]*")
SHA256 = re.compile(r"[0-9a-fA-F]{64}")
GIT_SHA = re.compile(r"[0-9a-fA-F]{40}")


def _read(root: Path, name: str) -> dict[str, Any]:
    data = json.loads((root / name).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected a release object in {name}")
    return data


def _field(record: dict[str, Any], name: str, pattern: re.Pattern[str]) -> str:
    value = record[name]
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"Invalid value for {name}")
    return value


def _receipt(root: Path, name: str) -> dict[str, Any]:
    path = PurePosixPath(name)
    if path.parent.as_posix() != "docs/releases" or path.suffix != ".json" or name == CATALOG:
        raise ValueError("Expected a separate JSON receipt under docs/releases")
    if (root / path).resolve().parent != (root / "docs/releases").resolve():
        raise ValueError("Release receipt escapes docs/releases")
    return _read(root, name)


def _windows(root: Path, catalog: dict[str, Any]) -> dict[str, Any]:
    primary = catalog["primary_windows_release"]
    version = _field(primary, "version", AGENT_VERSION)
    receipt = _receipt(root, primary["record"])
    if receipt["version"] != version:
        raise ValueError("Windows primary release version differs from its receipt")
    setup = receipt["setup"]
    if setup["download_published"] is not True:
        raise ValueError("Windows primary release receipt has no published download")
    sha256 = _field(setup, "sha256", SHA256)

    rollout = catalog["current_windows_rollout"]
    policy = rollout["policy"]
    rollout_id = str(UUID(policy["release_id"]))
    rollout_version = _field(rollout, "release", AGENT_VERSION)
    target_matches = rollout_id == str(UUID(receipt["full_setup_update"]["release_id"]))
    if target_matches and rollout_version != version:
        raise ValueError("Windows rollout version differs from the matching release receipt")
    if type(policy["enabled"]) is not bool:
        raise ValueError("Windows rollout enabled flag must be boolean")

    return {
        "primary": {
            "package_type": "setup_exe",
            "version": version,
            "release_id": str(UUID(setup["release_id"])),
            "sha256": sha256,
            "source_revision": _field(setup, "source_commit", GIT_SHA),
            "observed_at": receipt["verified_utc"],
            "record": primary["record"],
        },
        "enrollment": {"state": "unknown", "authority": "default_windows_auto_campaign"},
        "existing_device_delivery": {
            "package_type": "setup_exe",
            "version": rollout_version,
            "release_id": rollout_id,
            "sha256": sha256 if target_matches else None,
            "enabled": policy["enabled"],
            "observed_at": rollout["observed_at"],
        },
    }


def _alt(root: Path, catalog: dict[str, Any]) -> dict[str, Any]:
    primary = catalog["linux"]
    version = _field(primary, "version", AGENT_VERSION)
    receipt = _receipt(root, primary["release_record"])
    if receipt["version"] != version or receipt["primary_promoted"] is not True:
        raise ValueError("ALT primary release does not match its promoted receipt")
    kit, = (artifact for name, artifact in receipt["kit"].items() if name.endswith(".tar.gz"))
    core = receipt["native_packages"]["core"]
    if core["version"] != version:
        raise ValueError("ALT core RPM version differs from its release")
    source_id = str(UUID(primary["production_native_source_release_id"]))
    publication = receipt["source_publication"]
    if source_id != str(UUID(publication["release_id"])) or publication["environment"] != "production":
        raise ValueError("ALT enrollment source differs from its production publication")
    return {
        "primary": {
            "package_type": "rpm_kit",
            "version": version,
            "sha256": _field(kit, "sha256", SHA256),
            "source_revision": _field(receipt, "source_revision", GIT_SHA),
            "observed_at": receipt["verified_utc"],
            "record": primary["release_record"],
        },
        "enrollment": {
            "state": "catalog_recorded",
            "authority": "linux_native_registry_and_campaign",
            "package_type": "rpm",
            "version": version,
            "release_id": source_id,
            "sha256": _field(core, "sha256", SHA256),
            "observed_at": publication["observed_utc"],
        },
        "existing_device_delivery": {"state": "unknown", "authority": "linux_native_and_core_catalogs"},
    }


def _apt(record: dict[str, Any], suite: str) -> dict[str, Any]:
    if record["suite"] != suite:
        raise ValueError(f"Expected {suite} APT suite")
    return {
        "apt": {
            "package_type": "deb",
            "package": record["package"],
            "suite": suite,
            "version": _field(record, "version", PACKAGE_VERSION),
            "sha256": _field(record, "sha256", SHA256),
            "source_revision": _field(record, "runtime_source_commit", GIT_SHA),
            "evidence": record["verification"],
        }
    }


def status(root: Path) -> dict[str, Any]:
    catalog = _read(root, CATALOG)
    if type(catalog["schema_version"]) is not int or catalog["schema_version"] != 1:
        raise ValueError("Unsupported checked-in agent release record schema")
    provider = catalog["current_provider"]
    return {
        "schema_version": 1,
        "freshness": "repository_record",
        "source": CATALOG,
        "historical_checkpoint_version": _field(catalog, "version", AGENT_VERSION),
        "windows": _windows(root, catalog),
        "alt": _alt(root, catalog),
        "ubuntu": _apt(catalog["ubuntu_servers_197"], "noble"),
        "debian": _apt(catalog["proxmox_debian"], "bookworm"),
        "provider": {
            "source_revision": _field(provider, "source_commit", GIT_SHA),
            "sha256": _field(provider, "archive_sha256", SHA256),
            "observed_at": provider["publication_verified_utc"],
            "schema": provider["schema"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("status", help="show the checked-in release pointers as JSON")
    inspect.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    inspect.add_argument("--request-id", type=UUID, help="read one reservation and its candidates from Git")
    reserve = commands.add_parser("reserve", help="reserve the next Windows/ALT version in Git")
    reserve.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    agent_reservations.add_arguments(reserve)
    bind = commands.add_parser("bind-source", help="pin the candidate build commit to a reservation")
    bind.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    bind.add_argument("--request-id", required=True, type=UUID)
    candidate = commands.add_parser("record-candidate", help="pin native candidate bytes to a reservation")
    candidate.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    candidate.add_argument("--request-id", required=True, type=UUID)
    candidate.add_argument("--platform", required=True, choices=("windows", "alt"))
    candidate.add_argument("--manifest", required=True, type=Path, help="Setup sidecar or ALT kit manifest")
    candidate.add_argument("--expected-publisher", help="trusted Windows Setup/MSI publisher")
    candidate.add_argument("--archive-signature", type=Path, help="detached ALT kit signature")
    candidate.add_argument("--manifest-signature", type=Path, help="detached ALT manifest signature")
    reject = commands.add_parser("reject", help="record the rejection of an exact candidate digest")
    reject.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    reject.add_argument("--request-id", required=True, type=UUID)
    reject.add_argument("--platform", required=True, choices=("windows", "alt"))
    reject.add_argument("--sha256", required=True, help="digest of the Windows EXE or ALT kit archive")
    reject.add_argument("--reason", required=True, help="bounded reason for the release record")
    args = parser.parse_args()
    try:
        if args.command == "status":
            result = agent_reservations.reservation_status(args) if args.request_id else status(args.repo_root)
        elif args.command == "reserve":
            result = agent_reservations.reserve(args)
        elif args.command == "bind-source":
            result = agent_reservations.bind_source(args)
        elif args.command == "record-candidate":
            result = agent_reservations.record_candidate(args)
        else:
            result = agent_reservations.reject_candidate(args)
    except (OSError, KeyError, TypeError, ValueError, AttributeError, SyntaxError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"Agent release {args.command} failed: {exc}\n")
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
