"""Fingerprint native candidate bytes without registering or qualifying them."""

from argparse import Namespace
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile

from tools.release.linux_native_verifier import KEY_SHA256, MAX_RPM, PUBLISHER


MAX_METADATA = 64 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")


def _regular(path: Path, limit: int | None = None) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular file: {path.name}")
    size = path.stat().st_size
    if size == 0 or (limit is not None and size > limit):
        raise ValueError(f"Unexpected file size: {path.name}")


def _fingerprint(path: Path, limit: int | None = None) -> dict:
    _regular(path, limit)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(f"File changed while computing its digest: {path.name}")
    return {"filename": path.name, "size": after.st_size, "sha256": digest}


def _inspect_windows(args: Namespace, reservation: dict) -> dict:
    from tools.register_windows_setup_release import validate_release_inputs

    if not args.expected_publisher or args.archive_signature or args.manifest_signature:
        raise ValueError("Windows needs the expected publisher and Setup sidecar")
    version, revision = reservation["version"], reservation["build_revision"]
    setup = args.manifest.with_name(f"EndpointAgentSetup-{version}-x64.exe")
    msi = args.manifest.with_name(f"EndpointAgent-{version}-x64.msi")
    msi_manifest = msi.with_suffix(".release.json")
    artifacts = {
        "manifest": _fingerprint(args.manifest, MAX_METADATA),
        "msi_manifest": _fingerprint(msi_manifest, MAX_METADATA),
    }
    metadata = validate_release_inputs(args.manifest, setup, msi, msi_manifest,
                                       args.expected_publisher, candidate_only=True)
    if (metadata.version, metadata.agent_version, metadata.source_commit) != (version, version, revision):
        raise ValueError("Windows candidate version or source differs from the bound build")
    for key, path in (("manifest", args.manifest), ("msi_manifest", msi_manifest)):
        if artifacts[key] != _fingerprint(path, MAX_METADATA):
            raise ValueError(f"Metadata digest changed while checking candidate: {path.name}")
    for key, path, digest in (("setup", setup, metadata.setup_sha256), ("msi", msi, metadata.msi_sha256)):
        proof = _fingerprint(path)
        if proof["sha256"] != digest:
            raise ValueError(f"Artifact digest changed while checking candidate: {path.name}")
        artifacts[key] = proof
    return {"artifacts": artifacts, "publisher": args.expected_publisher,
            "msi_source_revision": metadata.msi_source_commit, "product_code": metadata.product_code}


def _inspect_alt(args: Namespace, reservation: dict) -> dict:
    if not args.archive_signature or not args.manifest_signature or args.expected_publisher:
        raise ValueError("ALT needs the detached archive and manifest signatures")
    version, revision = reservation["version"], reservation["build_revision"]
    name = f"endpoint-alt-pilot-{version}-1"
    archive = args.manifest.with_name(f"{name}.tar.gz")
    if (args.manifest.name != f"{name}.manifest.json"
            or args.archive_signature.name != f"{archive.name}.sig"
            or args.manifest_signature.name != f"{args.manifest.name}.sig"):
        raise ValueError("ALT kit and signature filenames must match the candidate version")
    _regular(args.manifest, MAX_METADATA)
    raw = args.manifest.read_bytes()
    manifest = json.loads(raw)
    if (manifest["schema_version"] != "endpoint_alt_native_kit_v3" or manifest["kit_name"] != name
            or manifest["agent_version"] != version or manifest["agent_source_revision"] != revision
            or manifest["publisher_fingerprint"] != PUBLISHER
            or not SHA256.fullmatch(manifest["frozen_manifest_sha256"])):
        raise ValueError("ALT kit version, publisher or source differs from the bound build")
    files = {
        filename: {"size": proof["size"], "sha256": proof["sha256"]}
        for filename, proof in manifest["files"].items()
    }
    fixed_names = {"endpoint-agent-setup", "endpoint-rpm-release.asc"}
    rpm_names = set(files) - fixed_names
    for package in ("endpoint-agent", "endpoint-agent-user-sensor"):
        rpm = re.compile(rf"{package}-{re.escape(version)}-[A-Za-z0-9.+_~]+\.x86_64\.rpm")
        if sum(bool(rpm.fullmatch(filename)) for filename in rpm_names) != 1:
            raise ValueError(f"ALT kit requires one exact {package} RPM")
    if len(rpm_names) != 2 or not fixed_names <= files.keys():
        raise ValueError("ALT kit needs exactly Core, UserSensor, Setup and the publisher key")
    for proof in files.values():
        if (type(proof["size"]) is not int or not 0 < proof["size"] <= MAX_RPM
                or not SHA256.fullmatch(proof["sha256"])):
            raise ValueError("Invalid ALT kit member size or digest")
    if files["endpoint-rpm-release.asc"]["sha256"] != KEY_SHA256:
        raise ValueError("ALT kit publisher key digest differs from the pinned key")
    metadata = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    archive_proof = _inspect_tar(archive, name, {**files, "native-kit-manifest.json": metadata})
    return {
        "artifacts": {
            "archive": archive_proof, "manifest": {"filename": args.manifest.name, **metadata},
            "archive_signature": _fingerprint(args.archive_signature, MAX_METADATA),
            "manifest_signature": _fingerprint(args.manifest_signature, MAX_METADATA),
        },
        "members": files,
        "publisher_fingerprint": PUBLISHER,
        "frozen_manifest_sha256": manifest["frozen_manifest_sha256"],
    }


def _inspect_tar(path: Path, folder: str, files: dict) -> dict:
    _regular(path, 3 * MAX_RPM + MAX_METADATA)
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            pending = {f"{folder}/{name}": proof for name, proof in files.items()}
            with tarfile.open(fileobj=stream, mode="r:gz") as archive:
                for member in archive:
                    proof = pending.pop(member.name, None)
                    if (proof is None or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                            or member.size != proof["size"]):
                        raise ValueError(f"Unexpected ALT kit member: {member.name!r}")
                    with archive.extractfile(member) as content:
                        if hashlib.file_digest(content, "sha256").hexdigest() != proof["sha256"]:
                            raise ValueError(f"ALT kit member digest differs from manifest: {member.name!r}")
            if pending:
                raise ValueError("ALT kit is missing listed members")
            stream.seek(0)
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("ALT kit changed while computing its digest")
    except (tarfile.TarError, EOFError) as exc:
        raise ValueError("Invalid ALT kit archive") from exc
    return {"filename": path.name, "size": after.st_size, "sha256": digest}


def inspect_candidate(args: Namespace, reservation: dict) -> dict:
    if args.platform == "windows":
        return _inspect_windows(args, reservation)
    return _inspect_alt(args, reservation)
