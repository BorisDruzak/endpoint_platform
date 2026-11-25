"""Activate one qualified version directory under the existing ALT HTTPS alias."""

from argparse import ArgumentParser, Namespace
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from uuid import UUID

from tools.release import agent_alt_download as download
from tools.release import agent_alt_qualification
from tools.release.agent_candidate_artifacts import MAX_METADATA, SHA256


_GUIDE_NAME = "README.ru.md"
_MODES = {"directory_mode": 0o755, "file_mode": 0o644}


def add_arguments(parser: ArgumentParser) -> None:
    download.add_https_arguments(parser)
    parser.add_argument("--qualification-id", required=True, type=UUID)
    parser.add_argument("--incoming-root", required=True, type=Path, help="Prepared owner-only staging root")
    parser.add_argument("--distribution-root", type=Path, default=Path("/srv/endpoint-platform-distribution/alt"))
    parser.add_argument("--guide", required=True, type=Path, help="Reviewed public guide for this exact version")
    parser.add_argument("--guide-sha256", required=True, help="Approved SHA-256 of the guide")
    parser.add_argument("--worker-user", required=True, help="Configured unprivileged Nginx worker account")
    parser.add_argument("--execute", action="store_true", help="Activate the qualified version directory")


def add_withdrawal_arguments(parser: ArgumentParser) -> None:
    download.add_https_arguments(parser)
    parser.add_argument("--sha256", required=True, help="Exact revoked ALT kit archive SHA-256")
    parser.add_argument("--distribution-root", type=Path, default=Path("/srv/endpoint-platform-distribution/alt"))
    parser.add_argument("--archive-root", required=True, type=Path, help="Existing owner-only private archive")
    parser.add_argument("--guide", required=True, type=Path, help="Retained reviewed public guide for this release")
    parser.add_argument("--guide-sha256", required=True, help="Previously approved SHA-256 of the guide")
    parser.add_argument("--execute", action="store_true", help="Move the revoked version outside the public alias")


def _read_guide(path, expected):
    if not SHA256.fullmatch(expected) or not path.is_file() or path.is_symlink():
        raise ValueError("ALT publication requires a regular guide and its approved guide digest")
    with path.open("rb") as stream:
        body = stream.read(MAX_METADATA + 1)
    if not 0 < len(body) <= MAX_METADATA or hashlib.sha256(body).hexdigest() != expected:
        raise ValueError("ALT publication guide digest or size differs from the approved guide")
    body.decode("utf-8")
    return body, {"filename": _GUIDE_NAME, "size": len(body), "sha256": expected}


def _check_distribution(root, incoming):
    if root == incoming or root in incoming.parents or incoming in root.parents:
        raise ValueError("ALT private staging and the public alias must be separate")
    if root.stat().st_dev != incoming.stat().st_dev:
        raise ValueError("ALT publication requires staging and distribution on the same filesystem")
    owner = os.geteuid()
    for directory in (root, *root.parents):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner)
                or (info.st_mode & 0o022 and not (directory != root and info.st_mode & stat.S_ISVTX))):
            raise ValueError("Unsafe ALT public distribution directory")
    if stat.S_IMODE(root.stat().st_mode) != _MODES["directory_mode"]:
        raise ValueError("ALT public distribution root must have mode 0755")


def _worker_run(user, *command, cwd=None):
    outcome = subprocess.run(["runuser", "-u", user, "--", *command], cwd=cwd, check=False,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if outcome.returncode:
        raise ValueError("The configured Nginx worker cannot read the ALT public payload")


def _activate(incoming, destination, paths, proofs, validate, check_worker, verify):
    from fcntl import LOCK_EX, flock

    fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        flock(fd, LOCK_EX)
        if os.path.lexists(destination):
            download._check_payload(destination, proofs, **_MODES)
            validate()
            verify()
            os.fsync(fd)
            return False
        with TemporaryDirectory(prefix=".publish-", dir=incoming) as scratch:
            payload = Path(scratch) / "payload"
            payload.mkdir(mode=0o700)
            payload.chmod(_MODES["directory_mode"])
            download._write_payload(payload, paths, proofs, **_MODES)
            check_worker(payload)
            download._sync_directory(payload)
            validate()
            source_identity = payload.stat()
            payload.rename(destination)
            try:
                os.fsync(fd)
                verify()
                validate()
            except BaseException:
                current = destination.lstat()
                if (current.st_dev, current.st_ino) != (source_identity.st_dev, source_identity.st_ino):
                    raise ValueError("ALT public directory ownership changed during verification")
                destination.rename(payload)
                os.fsync(fd)
                raise
        return True
    finally:
        os.close(fd)


def publish(args: Namespace) -> dict:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("ALT publication requires the protected Linux distribution host")
    import pwd

    candidate, qualification = agent_alt_qualification.require(args)
    origin = download._https_origin(args.origin)
    if pwd.getpwnam(args.worker_user).pw_uid == 0:
        raise ValueError("ALT publication expects an unprivileged Nginx worker account")
    incoming = Path(os.path.abspath(args.incoming_root))
    distribution = Path(os.path.abspath(args.distribution_root))
    download._check_root(incoming)
    _check_distribution(distribution, incoming)
    folder, proofs, _ = download._download_proofs(candidate)
    prepared = incoming / folder
    download._check_payload(prepared, proofs)
    paths = {name: prepared / name for name in proofs}
    paths[_GUIDE_NAME], proofs[_GUIDE_NAME] = _read_guide(args.guide, args.guide_sha256)
    destination = distribution / folder
    _worker_run(args.worker_user, "test", "-x", str(distribution))

    def validate():
        if agent_alt_qualification.require(args) != (candidate, qualification):
            raise ValueError("ALT publication qualification or candidate changed")

    def check_worker(payload):
        for name in proofs:
            _worker_run(args.worker_user, "head", "-c", "1", "--", name, cwd=payload)

    def verify():
        download._verify_https_files(origin, args.ca_file, folder, proofs, check_access=True)

    result = {"schema_version": 1, "platform": "alt", "scope": "first_enrollment",
              "request_id": candidate["request_id"], "qualification_id": qualification["qualification_id"],
              "kit_sha256": qualification["kit_sha256"], "directory": str(destination), "files": proofs}
    if not args.execute:
        if os.path.lexists(destination):
            download._check_payload(destination, proofs, **_MODES)
        return {**result, "state": "preview", "valid_until": qualification["valid_until"]}
    created = _activate(incoming, destination, paths, proofs, validate, check_worker, verify)
    return {**result, "state": "published", "new_directory": created,
            "url_prefix": f"https://{origin.netloc}/downloads/alt/{folder}/"}


def _withdraw(published, retained, proofs, verify, *, execute=True):
    from fcntl import LOCK_EX, flock

    fd = os.open(published.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        flock(fd, LOCK_EX)
        public_exists = os.path.lexists(published)
        retained_exists = os.path.lexists(retained)
        if public_exists and retained_exists:
            raise ValueError("ALT withdrawal conflicts with an existing private copy and a public directory")
        if public_exists or retained_exists:
            download._check_payload(published if public_exists else retained, proofs, **_MODES)
        if not execute:
            return "public" if public_exists else "archived" if retained_exists else "absent"
        if public_exists:
            published.rename(retained)
        if public_exists or retained_exists:
            download._sync_directory(retained.parent)
        os.fsync(fd)
        # A failed network probe leaves the revoked bytes private. Retry verifies the same archive.
        verify()
        return public_exists
    finally:
        os.close(fd)


def withdraw(args: Namespace) -> dict:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("ALT withdrawal requires the protected Linux distribution host")
    candidate, revoked = agent_alt_qualification.require_revocation(args)
    origin = download._https_origin(args.origin)
    archive = Path(os.path.abspath(args.archive_root))
    distribution = Path(os.path.abspath(args.distribution_root))
    download._check_root(archive)
    _check_distribution(distribution, archive)
    folder, proofs, _ = download._download_proofs(candidate)
    _, proofs[_GUIDE_NAME] = _read_guide(args.guide, args.guide_sha256)
    published, retained = distribution / folder, archive / folder

    def verify():
        download.verify_https_withdrawal(origin, args.ca_file, folder, proofs)

    result = {**revoked, "directory": str(published), "archive_directory": str(retained), "files": proofs}
    outcome = _withdraw(published, retained, proofs, verify, execute=args.execute)
    if not args.execute:
        return {**result, "state": "preview", "local_visibility": outcome}
    return {**result, "state": "withdrawn", "archived_now": outcome, "archive_exists": retained.exists(),
            "https_status": 404}
