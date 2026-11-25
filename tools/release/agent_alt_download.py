"""Prepare a private, immutable download payload from the verified ALT kit."""

from argparse import ArgumentParser, Namespace
import hashlib
import os
from pathlib import Path
import shutil
import stat
from tempfile import TemporaryDirectory

from tools.release import agent_alt_native
from tools.release.agent_candidate_artifacts import _fingerprint


def add_arguments(parser: ArgumentParser) -> None:
    agent_alt_native.add_kit_arguments(parser)
    parser.add_argument("--incoming-root", required=True, type=Path, help="Existing owner-only staging directory")
    parser.add_argument("--execute", action="store_true", help="Prepare the version directory privately")


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


def _payload(candidate, kit):
    paths = {}
    proofs = {}
    for label, proof in candidate["artifacts"].items():
        name = proof["filename"]
        paths[name] = kit.files[label]
        proofs[name] = proof
        if label in ("archive", "manifest"):
            sidecar_name = f"{name}.sha256"
            sidecar = f"{proof['sha256']}  {name}\n".encode("ascii")
            paths[sidecar_name] = sidecar
            proofs[sidecar_name] = {"filename": sidecar_name, "size": len(sidecar),
                                   "sha256": hashlib.sha256(sidecar).hexdigest()}
    key_name = "endpoint-rpm-release.asc"
    paths[key_name] = kit.public_key
    proofs[key_name] = {"filename": key_name, **candidate["members"][key_name]}
    return paths, proofs


def _check_payload(directory: Path, proofs) -> None:
    info = directory.lstat()
    owner = os.geteuid()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700
            or {entry.name for entry in directory.iterdir()} != proofs.keys()):
        raise ValueError("ALT download directory conflicts with the exact prepared payload")
    for name, proof in proofs.items():
        path = directory / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or _fingerprint(path, proof["size"]) != proof):
            raise ValueError(f"ALT download file conflicts with its retained digest: {name}")


def _write_payload(directory: Path, paths, proofs) -> None:
    for name, source in paths.items():
        with (directory / name).open("xb") as output:
            if isinstance(source, bytes):
                output.write(source)
            else:
                with source.open("rb") as stream:
                    shutil.copyfileobj(stream, output, length=1024 * 1024)
            output.flush()
            os.fchmod(output.fileno(), 0o600)
            os.fsync(output.fileno())
    _check_payload(directory, proofs)


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
            payload_fd = os.open(payload, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(payload_fd)
            finally:
                os.close(payload_fd)
            payload.rename(destination)
            os.fsync(fd)
        return "prepared"
    finally:
        os.close(fd)


def prepare(args: Namespace) -> dict:
    candidate = agent_alt_native.recorded_kit(args)
    root = Path(os.path.abspath(args.incoming_root))
    destination = root / f"endpoint-alt-pilot-{candidate['version']}-1"
    _check_root(root)
    with agent_alt_native.verified_kit(candidate, args) as kit:
        paths, proofs = _payload(candidate, kit)
        state = _prepare_directory(root, destination, paths, proofs, execute=args.execute)
    return {"schema_version": 1, "platform": "alt", "state": state, "request_id": candidate["request_id"],
            "directory": str(destination), "visibility": "private_staging", "files": proofs}
