"""Prepare a private, immutable download payload from the verified ALT kit."""

from argparse import ArgumentParser, Namespace
from contextlib import closing
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException, HTTPSConnection
import os
from pathlib import Path
import shutil
import ssl
import stat
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit
from uuid import UUID

from tools.release import agent_alt_native
from tools.release.agent_candidate_artifacts import MAX_METADATA, SHA256, _fingerprint, get_recorded_candidate
from tools.release.linux_native_verifier import KEY_SHA256, MAX_RPM


def add_arguments(parser: ArgumentParser) -> None:
    agent_alt_native.add_kit_arguments(parser)
    parser.add_argument("--incoming-root", required=True, type=Path, help="Existing owner-only staging directory")
    parser.add_argument("--execute", action="store_true", help="Prepare the version directory privately")


def add_https_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, default=agent_alt_native.ROOT)
    parser.add_argument("--request-id", type=UUID, required=True)
    parser.add_argument("--origin", required=True, help="Canonical HTTPS Endpoint origin")
    parser.add_argument("--ca-file", type=Path, required=True, help="Trusted CA for this Endpoint environment")


def _check_root(root: Path) -> None:
    owner = os.geteuid()
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("ALT download incoming root must be owned by the operator with mode 0700")
    for parent in root.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner)
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise ValueError("Unsafe ALT download staging path")


def _download_proofs(candidate):
    folder = f"endpoint-alt-pilot-{candidate['version']}-1"
    names = {"archive": f"{folder}.tar.gz", "manifest": f"{folder}.manifest.json",
             "archive_signature": f"{folder}.tar.gz.sig", "manifest_signature": f"{folder}.manifest.json.sig"}
    proofs = {}
    checksums = {}
    if candidate["artifacts"].keys() != names.keys():
        raise ValueError("Recorded ALT download requires exactly four signed-kit files")
    for label, name in names.items():
        proof = candidate["artifacts"][label]
        limit = 3 * MAX_RPM + MAX_METADATA if label == "archive" else MAX_METADATA
        if (proof["filename"] != name or type(proof["size"]) is not int or not 0 < proof["size"] <= limit
                or not SHA256.fullmatch(proof["sha256"])):
            raise ValueError("Recorded ALT download file identity is invalid")
        proofs[name] = proof
        if label in ("archive", "manifest"):
            sidecar_name = f"{name}.sha256"
            sidecar = f"{proof['sha256']}  {name}\n".encode("ascii")
            checksums[sidecar_name] = sidecar
            proofs[sidecar_name] = {"filename": sidecar_name, "size": len(sidecar),
                                   "sha256": hashlib.sha256(sidecar).hexdigest()}
    key_name = "endpoint-rpm-release.asc"
    key = candidate["members"][key_name]
    if (key["sha256"] != KEY_SHA256 or type(key["size"]) is not int or not 0 < key["size"] <= MAX_METADATA):
        raise ValueError("Recorded ALT download must bind the pinned publisher key")
    proofs[key_name] = {"filename": key_name, "size": key["size"], "sha256": key["sha256"]}
    return folder, proofs, checksums


def _check_payload(directory: Path, proofs, *, directory_mode=0o700, file_mode=0o600) -> None:
    info = directory.lstat()
    owner = os.geteuid()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != directory_mode
            or {entry.name for entry in directory.iterdir()} != proofs.keys()):
        raise ValueError("ALT download directory conflicts with the exact prepared payload")
    for name, proof in proofs.items():
        path = directory / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != file_mode or _fingerprint(path, proof["size"]) != proof):
            raise ValueError(f"ALT download file conflicts with its retained digest: {name}")


def _write_payload(directory: Path, paths, proofs, *, directory_mode=0o700, file_mode=0o600) -> None:
    for name, source in paths.items():
        with (directory / name).open("xb") as output:
            if isinstance(source, bytes):
                output.write(source)
            else:
                with source.open("rb") as stream:
                    shutil.copyfileobj(stream, output, length=1024 * 1024)
            output.flush()
            os.fchmod(output.fileno(), file_mode)
            os.fsync(output.fileno())
    _check_payload(directory, proofs, directory_mode=directory_mode, file_mode=file_mode)


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _prepare_directory(root: Path, destination: Path, paths, proofs, *, execute: bool) -> str:
    from fcntl import LOCK_EX, flock

    _check_root(root)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if execute:
            flock(fd, LOCK_EX)
        if os.path.lexists(destination):
            _check_payload(destination, proofs)
            if execute:
                os.fsync(fd)
            return "prepared" if execute else "preview"
        if not execute:
            return "preview"
        with TemporaryDirectory(prefix=".incoming-", dir=root) as scratch:
            payload = Path(scratch) / "payload"
            payload.mkdir(mode=0o700)
            _write_payload(payload, paths, proofs)
            _sync_directory(payload)
            payload.rename(destination)
            os.fsync(fd)
        return "prepared"
    finally:
        os.close(fd)


def prepare(args: Namespace) -> dict:
    candidate = agent_alt_native.recorded_kit(args)
    root = Path(os.path.abspath(args.incoming_root))
    folder, proofs, checksums = _download_proofs(candidate)
    destination = root / folder
    _check_root(root)
    with agent_alt_native.verified_kit(candidate, args) as kit:
        paths = {proof["filename"]: kit.files[label] for label, proof in candidate["artifacts"].items()}
        paths.update(checksums)
        paths["endpoint-rpm-release.asc"] = kit.public_key
        state = _prepare_directory(root, destination, paths, proofs, execute=args.execute)
    return {"schema_version": 1, "platform": "alt", "state": state, "request_id": candidate["request_id"],
            "directory": str(destination), "visibility": "private_staging", "files": proofs}


def _check_https_file(connection, prefix, name, proof):
    path = prefix + name
    for method in ("HEAD", "GET"):
        connection.request(method, path, headers={"Accept-Encoding": "identity"})
        with connection.getresponse() as response:
            if response.status != 200:
                raise ValueError(f"ALT download {method} returned {response.status}: {name}")
            if (response.getheader("Content-Length") != str(proof["size"])
                    or response.getheader("Transfer-Encoding") is not None
                    or response.getheader("Content-Encoding") not in (None, "identity")):
                raise ValueError(f"ALT download response size or encoding differs: {name}")
            if method == "HEAD":
                response.read()
                continue
            digest = hashlib.sha256()
            remaining = proof["size"]
            while remaining:
                chunk = response.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError(f"ALT download response ended early: {name}")
                remaining -= len(chunk)
                digest.update(chunk)
            if digest.hexdigest() != proof["sha256"]:
                raise ValueError(f"ALT download response digest differs: {name}")


def _https_origin(value):
    origin = urlsplit(value)
    if (origin.scheme != "https" or not origin.hostname or origin.path not in ("", "/")
            or origin.username is not None or origin.password is not None or origin.query or origin.fragment):
        raise ValueError("ALT download requires an absolute HTTPS origin")
    return origin


def _verify_https_files(origin, ca_file, folder, proofs, *, check_access=False) -> str:
    prefix = f"/downloads/alt/{folder}/"
    context = ssl.create_default_context(cafile=str(ca_file))
    try:
        with closing(HTTPSConnection(origin.hostname, origin.port, context=context, timeout=15)) as connection:
            for name, proof in proofs.items():
                _check_https_file(connection, prefix, name, proof)
            if check_access:
                for method, path in (("GET", prefix), ("OPTIONS", prefix + folder + ".tar.gz")):
                    connection.request(method, path)
                    with connection.getresponse() as response:
                        if response.status not in (403, 404, 405):
                            raise ValueError(f"ALT download access probe {method} returned {response.status}")
                    connection.close()
    except HTTPException as exc:
        raise ValueError("Invalid ALT HTTPS download response") from exc
    return f"https://{origin.netloc}{prefix}"


def verify_https(args: Namespace) -> dict:
    origin = _https_origin(args.origin)
    candidate = get_recorded_candidate(agent_alt_native.agent_reservations.reservation_status(args), "alt")
    folder, proofs, _ = _download_proofs(candidate)
    prefix = _verify_https_files(origin, args.ca_file, folder, proofs)
    return {"schema_version": 1, "platform": "alt", "state": "https_verified", "request_id": candidate["request_id"],
            "checked_at": datetime.now(timezone.utc).isoformat(), "url_prefix": prefix,
            "files": proofs}
