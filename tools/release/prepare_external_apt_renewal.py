"""Prepare and verify APT renewal using a separate signing workstation."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

if __package__:
    from . import build_ubuntu_apt_repository as apt
else:
    import build_ubuntu_apt_repository as apt


def _workspace(root: Path, workspace: Path) -> Path:
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir() or workspace.is_relative_to(root.resolve(strict=True)):
        raise ValueError("renewal workspace must be a directory outside the repository")
    return workspace


def _verified_metadata(payload: bytes, keyring: Path, fingerprint: str) -> str:
    with TemporaryDirectory(prefix="endpoint-apt-external-") as scratch:
        signed = Path(scratch) / "InRelease"
        signed.write_bytes(payload)
        return apt._verified_release(signed, keyring, fingerprint)


def draft(
    root: Path, workspace: Path, keyring: Path, fingerprint: str, *,
    codename: str, now: datetime | None = None,
) -> dict[str, str | None]:
    workspace = _workspace(root, workspace)
    now = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    suite = root / "dists" / codename
    source = suite / "InRelease"
    original = apt._read_inrelease(source)
    metadata = _verified_metadata(original, keyring, fingerprint)
    expiry = apt._renewal_expiry(metadata, codename, now, only_if_due=True)
    apt._verify_indexes(root, suite, metadata)
    if apt._read_inrelease(source) != original:
        raise ValueError("live source changed since the renewal draft began")
    source_sha = hashlib.sha256(original).hexdigest()
    if expiry is None:
        return {"source_sha256": source_sha, "draft_sha256": None}

    proposed = apt._updated_release(metadata, now, expiry).encode("utf-8")
    with (workspace / "Release").open("xb") as output:
        output.write(proposed)
    request = {"source_sha256": source_sha, "draft_sha256": hashlib.sha256(proposed).hexdigest()}
    with (workspace / "request.json").open("x", encoding="utf-8") as output:
        json.dump(request, output)
    return request


def verify(
    root: Path, workspace: Path, keyring: Path, fingerprint: str, signer: str, *,
    codename: str, now: datetime | None = None,
) -> dict[str, str]:
    workspace = _workspace(root, workspace)
    now = (now or datetime.now(UTC)).astimezone(UTC)
    request = json.loads((workspace / "request.json").read_text(encoding="utf-8"))
    suite = root / "dists" / codename
    source = suite / "InRelease"
    original = apt._read_inrelease(source)
    source_sha = hashlib.sha256(original).hexdigest()
    if source_sha != request["source_sha256"]:
        raise ValueError("live source changed since preparation")
    old = _verified_metadata(original, keyring, fingerprint)
    draft_bytes = apt._read_inrelease(workspace / "Release")
    candidate = workspace / "InRelease"
    signed = apt._read_inrelease(candidate)
    new = _verified_metadata(signed, keyring, signer)
    if hashlib.sha256(draft_bytes).hexdigest() != request["draft_sha256"] or new.encode("utf-8") != draft_bytes:
        raise ValueError("signed InRelease differs from the renewal draft")
    expiry = apt._verify_renewed_metadata(old, new, codename, now)
    apt._verify_indexes(root, suite, new)
    if apt._read_inrelease(source) != original or apt._read_inrelease(candidate) != signed:
        raise ValueError("source or candidate changed during verification")
    return {
        "source_sha256": source_sha,
        "candidate_sha256": hashlib.sha256(signed).hexdigest(),
        "valid_until": expiry.isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("draft", "verify"))
    parser.add_argument("repository", type=Path)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("keyring", type=Path)
    parser.add_argument("codename", choices=apt.REPOSITORIES)
    parser.add_argument("publisher")
    parser.add_argument("--successor")
    args = parser.parse_args()
    inputs = (args.repository, args.workspace, args.keyring, args.publisher)
    if args.action == "draft":
        result = draft(*inputs, codename=args.codename)
    else:
        result = verify(*inputs, args.successor or args.publisher, codename=args.codename)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
