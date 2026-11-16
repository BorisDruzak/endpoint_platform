"""Build and maintain signed Endpoint agent repositories from immutable DEBs."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime, parsedate_to_datetime
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory


SUITE = "noble"
REPOSITORIES = {
    "noble": ("endpoint-agent-ubuntu", re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-1ubuntu[0-9]+")),
    "bookworm": ("endpoint-agent-debian", re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-1deb12u[0-9]+")),
}
FINGERPRINT = re.compile(r"[A-Fa-f0-9]{40}")
VALIDITY = timedelta(days=7)
RENEWAL_WARNING = timedelta(days=3)
INRELEASE_LIMIT = 1024 * 1024


def _sign_release(release: Path, output: Path, fingerprint: str) -> None:
    subprocess.run([
        "gpg", "--batch", "--local-user", fingerprint,
        "--output", output, "--clearsign", release,
    ], check=True, timeout=60)


def _verified_release(path: Path, keyring: Path, fingerprint: str) -> str:
    if not FINGERPRINT.fullmatch(fingerprint):
        raise ValueError("use the full OpenPGP signing-key fingerprint")
    if not path.is_file() or path.is_symlink() or path.stat().st_size > INRELEASE_LIMIT:
        raise ValueError("unexpected InRelease file")
    verified = subprocess.run(
        ["gpgv", "--keyring", keyring.resolve(strict=True), "--status-fd", "2",
         "--output", "-", path],
        check=True, capture_output=True, timeout=15,
    )
    signatures = [
        line.split() for line in verified.stderr.decode("ascii", errors="replace").splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ")
    ]
    if len(signatures) != 1 or len(signatures[0]) < 11 or fingerprint.upper() not in {
        signatures[0][2], signatures[0][11] if len(signatures[0]) > 11 else "",
    }:
        raise ValueError("InRelease signer does not match the pinned fingerprint")
    return verified.stdout.decode("utf-8")


def _release_dates(metadata: str, codename: str = SUITE) -> tuple[datetime, datetime]:
    def read(name: str) -> datetime:
        values = re.findall(rf"^{name}: (.+)$", metadata, re.MULTILINE)
        if len(values) != 1:
            raise ValueError(f"expected exactly one {name} field")
        date = parsedate_to_datetime(values[0])
        if date.tzinfo is None:
            raise ValueError(f"{name} must include a timezone")
        return date.astimezone(UTC)

    date, expires = read("Date"), read("Valid-Until")
    if expires <= date or re.findall(r"^Codename: (.+)$", metadata, re.MULTILINE) != [codename]:
        raise ValueError("unexpected repository dates or codename")
    return date, expires


def _verify_hash(root: Path, name: str, size: str, digest: str) -> None:
    if any(part in {"", ".", ".."} for part in name.split("/")) or "\\" in name or ":" in name:
        raise ValueError("invalid signed file path")
    path = root / name
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("signed file path escapes repository")
    if not path.is_file() or path.stat().st_size != int(size):
        raise ValueError(f"signed file size or hash differs: {name}")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            raise ValueError(f"signed file hash differs: {name}")


def _verify_indexes(root: Path, suite: Path, metadata: str) -> None:
    hashes = re.findall(r"^SHA256:\n((?:[ \t]+[^\n]+\n)+)", metadata, re.MULTILINE)
    if len(hashes) != 1:
        raise ValueError("Release must contain a SHA256 index")
    seen: set[str] = set()
    for row in hashes[0].splitlines():
        match = re.fullmatch(r"\s*([a-f0-9]{64})\s+(\d+)\s+(\S+)", row)
        if match is None:
            raise ValueError("invalid Release hash entry")
        digest, size, name = match.groups()
        if name in seen:
            raise ValueError("duplicate Release hash path")
        _verify_hash(suite, name, size, digest)
        seen.add(name)
    packages = "main/binary-amd64/Packages"
    if packages not in seen:
        raise ValueError("Release omits the amd64 Packages index")
    entries = (suite / packages).read_text(encoding="utf-8").strip().split("\n\n")
    for entry in entries:
        fields = re.findall(r"^(Filename|Size|SHA256): (\S+)$", entry, re.MULTILINE)
        values = dict(fields)
        if (
            len(fields) != 3 or set(values) != {"Filename", "Size", "SHA256"}
            or not re.fullmatch(r"pool/[^\s]+\.deb", values["Filename"])
            or not re.fullmatch(r"[0-9]+", values["Size"])
            or not re.fullmatch(r"[a-f0-9]{64}", values["SHA256"])
        ):
            raise ValueError("invalid package hash entry")
        _verify_hash(root, values["Filename"], values["Size"], values["SHA256"])


def renew(
    root: Path, keyring: Path, fingerprint: str, *, now: datetime | None = None, codename: str = SUITE,
    only_if_due: bool = False,
) -> datetime | None:
    """Return the new expiry, or None if verified metadata is still fresh."""
    now = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    if codename not in REPOSITORIES:
        raise ValueError("unsupported APT codename")
    suite = root / "dists" / codename
    current = suite / "InRelease"
    metadata = _verified_release(current, keyring, fingerprint)
    valid_until = _renewal_expiry(metadata, codename, now, only_if_due=only_if_due)
    _verify_indexes(root, suite, metadata)
    if valid_until is None:
        return None
    renewed = _updated_release(metadata, now, valid_until)
    with TemporaryDirectory(prefix=".apt-renew-", dir=suite) as scratch:
        release, signed = _signed_release_files(Path(scratch), renewed, keyring, fingerprint)
        _replace_metadata(suite, release, signed)
    return valid_until


def _renewal_expiry(metadata: str, codename: str, now: datetime, *, only_if_due: bool) -> datetime | None:
    date, expires = _release_dates(metadata, codename)
    if only_if_due and date > now:
        raise ValueError("APT metadata is dated in the future")
    if only_if_due and expires > now + RENEWAL_WARNING:
        return None
    if now <= date or now + VALIDITY <= expires:
        raise ValueError("renewal must advance the signed repository dates")
    return now + VALIDITY


def _updated_release(metadata: str, now: datetime, valid_until: datetime) -> str:
    metadata = re.sub(r"^Date: .+$", f"Date: {format_datetime(now, usegmt=True)}", metadata, flags=re.MULTILINE)
    return re.sub(r"^Valid-Until: .+$", f"Valid-Until: {format_datetime(valid_until, usegmt=True)}",
                  metadata, flags=re.MULTILINE)


def _signed_release_files(
    directory: Path, metadata: str, keyring: Path, fingerprint: str,
) -> tuple[Path, Path]:
    release, signed = directory / "Release", directory / "InRelease"
    release.write_bytes(metadata.encode("utf-8"))
    _sign_release(release, signed, fingerprint)
    if _verified_release(signed, keyring, fingerprint) != metadata:
        raise ValueError("new InRelease does not match proposed metadata")
    return release, signed


def _replace_metadata(suite: Path, release: Path, signed: Path) -> None:
    release.chmod(0o644)
    signed.chmod(0o644)
    release.replace(suite / "Release")
    signed.replace(suite / "InRelease")


def _read_inrelease(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("unexpected InRelease file")
    with path.open("rb") as stream:
        payload = stream.read(INRELEASE_LIMIT + 1)
    if len(payload) > INRELEASE_LIMIT:
        raise ValueError("unexpected InRelease file")
    return payload


def _without_release_dates(metadata: str) -> str:
    return re.sub(r"^(Date|Valid-Until): .+$", r"\1:", metadata, flags=re.MULTILINE)


def _verify_renewed_metadata(
    old: str, new: str, codename: str, now: datetime, *, allow_expired: bool = False,
) -> datetime:
    old_date, old_expiry = _release_dates(old, codename)
    new_date, new_expiry = _release_dates(new, codename)
    if (
        new_date <= old_date
        or new_date > now + timedelta(seconds=10)
        or new_expiry <= old_expiry
        or (not allow_expired and new_expiry <= now)
        or new_expiry - new_date != VALIDITY
    ):
        raise ValueError("unexpected APT renewal dates")
    if _without_release_dates(old) != _without_release_dates(new):
        raise ValueError("renewal may change only Date and Valid-Until")
    return new_expiry


def prepare_renewal(
    root: Path, output: Path, keyring: Path, fingerprint: str, *,
    now: datetime | None = None, codename: str = SUITE, successor_fingerprint: str | None = None,
) -> Path | None:
    """Verify the live signer and prepare a date-only renewal outside its repository."""
    now = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    if codename not in REPOSITORIES:
        raise ValueError("unsupported APT codename")
    signer = fingerprint if successor_fingerprint is None else successor_fingerprint.upper()
    if not FINGERPRINT.fullmatch(signer):
        raise ValueError("use the full OpenPGP signing-key fingerprint")
    suite = root / "dists" / codename
    source = suite / "InRelease"
    original = _read_inrelease(source)
    source_sha = hashlib.sha256(original).hexdigest()
    destination_root = output / codename
    if signer.upper() != fingerprint.upper():
        destination_root /= f"successor-{signer}"
    destination_root /= source_sha
    if destination_root.resolve().is_relative_to(root.resolve()):
        raise ValueError("renewal output must be outside the published repository")

    with TemporaryDirectory(prefix="endpoint-apt-original-") as temporary:
        verified_copy = Path(temporary) / "InRelease"
        verified_copy.write_bytes(original)
        metadata = _verified_release(verified_copy, keyring, fingerprint)
    valid_until = _renewal_expiry(metadata, codename, now, only_if_due=True)
    _verify_indexes(root, suite, metadata)
    if _read_inrelease(source) != original:
        raise ValueError("live InRelease changed during preparation")
    if valid_until is None:
        return None

    destination = destination_root
    previous = metadata
    while True:
        candidate = destination / "InRelease"
        if candidate.resolve().is_relative_to(root.resolve()):
            raise ValueError("renewal output must be outside the published repository")
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix=".apt-prepare-", dir=destination.parent) as scratch:
                bundle = Path(scratch) / "renewal"
                bundle.mkdir()
                renewed = _updated_release(metadata, now, valid_until)
                release, _ = _signed_release_files(bundle, renewed, keyring, signer)
                release.unlink()
                if _read_inrelease(source) != original:
                    raise ValueError("live InRelease changed during preparation")
                try:
                    bundle.rename(destination)
                except OSError:
                    if not candidate.is_file():
                        raise
        prepared = _verified_release(candidate, keyring, signer)
        expires = _verify_renewed_metadata(previous, prepared, codename, now, allow_expired=True)
        if expires > now:
            return candidate
        # An expired candidate stays intact for audit and any publisher holding its path.
        previous = prepared
        destination = destination_root / f"after-{expires:%Y%m%dT%H%M%SZ}"


def publish_renewal(
    root: Path, candidate: Path, expected_sha256: str, keyring: Path, fingerprint: str, *,
    now: datetime | None = None, codename: str = SUITE, successor_fingerprint: str | None = None,
) -> datetime:
    """Install a signed date-only renewal while the caller excludes other publishers."""
    now = (now or datetime.now(UTC)).astimezone(UTC)
    if codename not in REPOSITORIES:
        raise ValueError("unsupported APT codename")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("expected the original live InRelease SHA-256")
    suite = root / "dists" / codename
    current = suite / "InRelease"
    original = _read_inrelease(current)
    if hashlib.sha256(original).hexdigest() != expected_sha256:
        raise ValueError("live InRelease changed since preparation")

    # Verify private copies so the exact candidate bytes checked are the bytes published.
    with TemporaryDirectory(prefix=".apt-publish-", dir=suite) as scratch:
        original_copy = Path(scratch) / "Original"
        original_copy.write_bytes(original)
        signed = Path(scratch) / "InRelease"
        signed.write_bytes(_read_inrelease(candidate))
        old = _verified_release(original_copy, keyring, fingerprint)
        expected_signer = fingerprint if successor_fingerprint is None else successor_fingerprint
        new = _verified_release(signed, keyring, expected_signer)
        new_expiry = _verify_renewed_metadata(old, new, codename, now)
        _verify_indexes(root, suite, new)
        release = Path(scratch) / "Release"
        release.write_bytes(new.encode("utf-8"))
        if _read_inrelease(current) != original:
            raise ValueError("live InRelease changed since preparation")
        _replace_metadata(suite, release, signed)
    return new_expiry


def build(artifacts: list[Path], output: Path, fingerprint: str, *, codename: str = SUITE) -> None:
    if codename not in REPOSITORIES:
        raise ValueError("unsupported APT codename")
    expected_package, version_pattern = REPOSITORIES[codename]
    if not FINGERPRINT.fullmatch(fingerprint):
        raise ValueError("use the full OpenPGP signing-key fingerprint")
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    if not artifacts:
        raise ValueError("at least one DEB is required")

    output = output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".endpoint-apt-", dir=output.parent) as temporary:
        root = Path(temporary) / "repository"
        pool = root / "pool"
        suite = root / "dists" / codename
        index = suite / "main" / "binary-amd64"
        pool.mkdir(parents=True)
        index.mkdir(parents=True)
        for artifact in artifacts:
            package, version, architecture = [
                subprocess.check_output(["dpkg-deb", "--field", artifact, field], text=True).strip()
                for field in ("Package", "Version", "Architecture")
            ]
            if package != expected_package or architecture != "amd64" or not version_pattern.fullmatch(version):
                raise ValueError(f"unexpected {codename} package metadata in {artifact.name}")
            destination = pool / f"{expected_package}_{version}_amd64.deb"
            if destination.exists():
                raise ValueError(f"duplicate {codename} package version {version}")
            shutil.copyfile(artifact, destination)
        with (index / "Packages").open("wb") as packages:
            subprocess.run(["apt-ftparchive", "packages", "pool"], cwd=root, stdout=packages, check=True)

        metadata = subprocess.check_output([
            "apt-ftparchive",
            "-o", "APT::FTPArchive::Release::Origin=Endpoint Platform",
            "-o", f"APT::FTPArchive::Release::Suite={codename}",
            "-o", f"APT::FTPArchive::Release::Codename={codename}",
            "-o", "APT::FTPArchive::Release::Architectures=amd64",
            "-o", "APT::FTPArchive::Release::Components=main",
            "release", f"dists/{codename}",
        ], cwd=root, text=True)
        valid_until = format_datetime(datetime.now(UTC) + VALIDITY, usegmt=True)
        (suite / "Release").write_text(f"Valid-Until: {valid_until}\n{metadata}", encoding="utf-8")
        _sign_release(suite / "Release", suite / "InRelease", fingerprint)
        root.rename(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--deb", type=Path, action="append")
    actions.add_argument("--renew", type=Path, metavar="REPOSITORY")
    actions.add_argument("--renew-if-due", type=Path, metavar="REPOSITORY",
                         help="verify the staging tree and sign when at most three days remain")
    actions.add_argument("--check", type=Path, metavar="INRELEASE")
    actions.add_argument("--prepare-renewal", type=Path, metavar="PUBLISHED_REPOSITORY")
    actions.add_argument("--publish-renewal", type=Path, metavar="LIVE_REPOSITORY")
    parser.add_argument("--from-inrelease", type=Path, metavar="SIGNED_RENEWAL")
    parser.add_argument("--expected-inrelease-sha256", metavar="SHA256")
    parser.add_argument("--successor-fingerprint", metavar="OPENPGP_FINGERPRINT",
                        help="prepare or verify a renewal signed by this key during a publisher transition")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--codename", choices=REPOSITORIES, default=SUITE)
    parser.add_argument("--signing-fingerprint", required=True)
    args = parser.parse_args()
    if args.publish_renewal is not None:
        if args.from_inrelease is None or args.expected_inrelease_sha256 is None or args.keyring is None:
            parser.error("--publish-renewal requires --from-inrelease, --expected-inrelease-sha256 and --keyring")
        expiry = publish_renewal(
            args.publish_renewal, args.from_inrelease, args.expected_inrelease_sha256,
            args.keyring, args.signing_fingerprint, codename=args.codename,
            successor_fingerprint=args.successor_fingerprint,
        )
        print(f"Published Valid-Until {expiry.isoformat()}")
        return
    if args.from_inrelease is not None or args.expected_inrelease_sha256 is not None:
        parser.error("publication inputs require --publish-renewal")
    if args.successor_fingerprint is not None and args.prepare_renewal is None:
        parser.error("--successor-fingerprint requires --prepare-renewal or --publish-renewal")
    if args.deb:
        if args.output is None:
            parser.error("--deb requires --output")
        build(args.deb, args.output, args.signing_fingerprint, codename=args.codename)
        return
    if args.keyring is None:
        parser.error("verification and renewal require --keyring")
    if args.prepare_renewal is not None:
        if args.output is None:
            parser.error("--prepare-renewal requires --output")
        candidate = prepare_renewal(
            args.prepare_renewal, args.output, args.keyring, args.signing_fingerprint, codename=args.codename,
            successor_fingerprint=args.successor_fingerprint,
        )
        if candidate is None:
            print("Verified repository: renewal not due")
        else:
            print(f"Prepared renewal {candidate}")
        return
    repository = args.renew or args.renew_if_due
    if repository is not None:
        expiry = renew(repository, args.keyring, args.signing_fingerprint, codename=args.codename,
                       only_if_due=args.renew_if_due is not None)
        if expiry is None:
            print("Verified repository: renewal not due")
        else:
            print(f"Renewed Valid-Until {expiry.isoformat()}")
        return
    metadata = _verified_release(args.check, args.keyring, args.signing_fingerprint)
    date, expiry = _release_dates(metadata, args.codename)
    now = datetime.now(UTC)
    if date > now + timedelta(seconds=10):
        raise SystemExit("APT metadata is dated in the future")
    print(f"Valid-Until {expiry.isoformat()}")
    if expiry <= now + RENEWAL_WARNING:
        raise SystemExit("APT metadata has expired or has at most three days remaining")


if __name__ == "__main__":
    main()
