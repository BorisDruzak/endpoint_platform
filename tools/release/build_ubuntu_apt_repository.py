"""Build a signed Ubuntu Server agent repository from immutable DEB artifacts."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory


SUITE = "noble"
PACKAGE = "endpoint-agent-ubuntu"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-1ubuntu[0-9]+")
FINGERPRINT = re.compile(r"[A-Fa-f0-9]{40}")


def build(artifacts: list[Path], output: Path, fingerprint: str) -> None:
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
        suite = root / "dists" / SUITE
        index = suite / "main" / "binary-amd64"
        pool.mkdir(parents=True)
        index.mkdir(parents=True)
        for artifact in artifacts:
            package, version, architecture = [
                subprocess.check_output(["dpkg-deb", "--field", artifact, field], text=True).strip()
                for field in ("Package", "Version", "Architecture")
            ]
            if package != PACKAGE or architecture != "amd64" or not VERSION.fullmatch(version):
                raise ValueError(f"unexpected Ubuntu package metadata in {artifact.name}")
            destination = pool / f"{PACKAGE}_{version}_amd64.deb"
            if destination.exists():
                raise ValueError(f"duplicate Ubuntu package version {version}")
            shutil.copyfile(artifact, destination)
        with (index / "Packages").open("wb") as packages:
            subprocess.run(["apt-ftparchive", "packages", "pool"], cwd=root, stdout=packages, check=True)

        metadata = subprocess.check_output([
            "apt-ftparchive",
            "-o", "APT::FTPArchive::Release::Origin=Endpoint Platform",
            "-o", f"APT::FTPArchive::Release::Suite={SUITE}",
            "-o", f"APT::FTPArchive::Release::Codename={SUITE}",
            "-o", "APT::FTPArchive::Release::Architectures=amd64",
            "-o", "APT::FTPArchive::Release::Components=main",
            "release", f"dists/{SUITE}",
        ], cwd=root, text=True)
        valid_until = format_datetime(datetime.now(UTC) + timedelta(days=7), usegmt=True)
        (suite / "Release").write_text(f"Valid-Until: {valid_until}\n{metadata}", encoding="utf-8")
        subprocess.run([
            "gpg", "--batch", "--local-user", fingerprint,
            "--output", "InRelease", "--clearsign", "Release",
        ], cwd=suite, check=True)
        root.rename(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deb", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-fingerprint", required=True)
    args = parser.parse_args()
    build(args.deb, args.output, args.signing_fingerprint)


if __name__ == "__main__":
    main()
