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


def _sign_release(release: Path, output: Path, fingerprint: str) -> None:
    subprocess.run([
        "gpg", "--batch", "--local-user", fingerprint,
        "--output", output, "--clearsign", release,
    ], check=True, timeout=60)


def _verified_release(path: Path, keyring: Path, fingerprint: str) -> str:
    if not FINGERPRINT.fullmatch(fingerprint):
        raise ValueError("use the full OpenPGP signing-key fingerprint")
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
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
    date, expires = _release_dates(metadata, codename)
    if only_if_due and date > now:
        raise ValueError("APT metadata is dated in the future")
    should_renew = not only_if_due or expires <= now + RENEWAL_WARNING
    if should_renew and (now <= date or now + VALIDITY <= expires):
        raise ValueError("renewal must advance the signed repository dates")
    _verify_indexes(root, suite, metadata)
    if not should_renew:
        return None
    valid_until = now + VALIDITY
    metadata = re.sub(r"^Date: .+$", f"Date: {format_datetime(now, usegmt=True)}", metadata, flags=re.MULTILINE)
    metadata = re.sub(r"^Valid-Until: .+$",
                      f"Valid-Until: {format_datetime(valid_until, usegmt=True)}", metadata, flags=re.MULTILINE)
    with TemporaryDirectory(prefix=".apt-renew-", dir=suite) as scratch:
        release, signed = Path(scratch) / "Release", Path(scratch) / "InRelease"
        release.write_bytes(metadata.encode("utf-8"))
        _sign_release(release, signed, fingerprint)
        if _verified_release(signed, keyring, fingerprint) != metadata:
            raise ValueError("new InRelease does not match proposed metadata")
        signed.chmod(0o644)
        release.chmod(0o644)
        release.replace(suite / "Release")
        signed.replace(current)
    return valid_until


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
    parser.add_argument("--output", type=Path)
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--codename", choices=REPOSITORIES, default=SUITE)
    parser.add_argument("--signing-fingerprint", required=True)
    args = parser.parse_args()
    if args.deb:
        if args.output is None:
            parser.error("--deb requires --output")
        build(args.deb, args.output, args.signing_fingerprint, codename=args.codename)
        return
    if args.keyring is None:
        parser.error("--renew, --renew-if-due and --check require --keyring")
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
