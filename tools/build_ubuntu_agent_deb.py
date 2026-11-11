"""Package the frozen Endpoint Core built on Ubuntu Server 24.04 amd64."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "endpoint-agent-ubuntu"
CORE_EXECUTABLE = "endpoint-agent"
VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")
RELEASE_REVISION = re.compile(r"[a-f0-9]{40}")


def build(core: Path, output: Path, *, version: str, source_revision: str) -> Path:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Ubuntu agent packages must be built on Linux x86_64")
    release = platform.freedesktop_os_release()
    if (release.get("ID"), release.get("VERSION_ID")) != ("ubuntu", "24.04"):
        raise ValueError("Ubuntu agent packages require an Ubuntu 24.04 build host")
    if not VERSION.fullmatch(version) or not RELEASE_REVISION.fullmatch(source_revision):
        raise ValueError("version and source revision must be canonical")
    if core.is_symlink():
        raise ValueError("the frozen core must be a directory")
    core = core.resolve(strict=True)
    executable = core / CORE_EXECUTABLE
    if executable.is_symlink() or not executable.is_file() or not (core / "_internal").is_dir():
        raise ValueError("the frozen core must contain endpoint-agent and _internal")
    if (core / "current.json").exists() or (core / "current.json").is_symlink():
        raise ValueError("current.json is reserved for the package selector")
    for path in core.rglob("*"):
        if path.is_symlink() and (
            path.readlink().is_absolute() or not path.resolve(strict=True).is_relative_to(core)
        ):
            raise ValueError(f"core symlink cannot be relocated: {path.relative_to(core)}")
    reported = subprocess.run(
        [executable, "--print-version"], check=True, text=True, capture_output=True, timeout=15,
    ).stdout.strip()
    if reported != version:
        raise ValueError(f"frozen core reports {reported!r} instead of {version!r}")

    package_version = f"{version}-1ubuntu1"
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / f"{PACKAGE}_{package_version}_amd64.deb"
    if artifact.exists():
        raise FileExistsError(artifact)
    packaging = ROOT / "packaging" / "ubuntu"
    with tempfile.TemporaryDirectory(prefix=f"{PACKAGE}-", dir=output) as temporary:
        scratch = Path(temporary)
        tree = scratch / "package"
        runtime = tree / "usr" / "lib" / PACKAGE
        shutil.copytree(core, runtime, symlinks=True)
        for path in runtime.rglob("*"):
            if path.is_symlink() and not path.resolve().is_relative_to(runtime):
                raise ValueError(f"relocated core symlink leaves its payload: {path.relative_to(runtime)}")
        (runtime / "current.json").write_text(
            json.dumps({"schema_version": 1, "source_revision": source_revision, "version": version})
            + "\n",
            encoding="utf-8",
        )
        for source, destination in (
            ("endpoint-agent-ubuntu.service", f"usr/lib/systemd/system/{PACKAGE}.service"),
            ("sysusers.conf", f"usr/lib/sysusers.d/{PACKAGE}.conf"),
            ("tmpfiles.conf", f"usr/lib/tmpfiles.d/{PACKAGE}.conf"),
            ("agent.conf", f"etc/{PACKAGE}/agent.conf"),
        ):
            target = tree / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((packaging / source).read_bytes().replace(b"\r\n", b"\n"))
            target.chmod(0o644)
        metadata = tree / "DEBIAN"
        metadata.mkdir()
        (metadata / "conffiles").write_text(f"/etc/{PACKAGE}/agent.conf\n", encoding="ascii")
        installed_bytes = sum(
            path.lstat().st_size for path in tree.rglob("*") if not path.is_symlink()
        )
        (metadata / "control").write_text(
            f"Package: {PACKAGE}\n"
            f"Version: {package_version}\n"
            "Section: admin\n"
            "Priority: optional\n"
            "Architecture: amd64\n"
            "Maintainer: Endpoint Platform\n"
            "Depends: libc6 (>= 2.39), systemd, init-system-helpers, iproute2, util-linux\n"
            f"Installed-Size: {(installed_bytes + 1023) // 1024}\n"
            "Description: Endpoint Platform agent for Ubuntu Server\n"
            " Collects host and server-role context through the Endpoint Gateway.\n",
            encoding="ascii",
        )
        for name in ("postinst", "prerm", "postrm"):
            script = metadata / name
            script.write_bytes((packaging / name).read_bytes().replace(b"\r\n", b"\n"))
            script.chmod(0o755)
        candidate = scratch / artifact.name
        subprocess.run(
            ["dpkg-deb", "--root-owner-group", "--build", tree, candidate], check=True,
        )
        artifact.hardlink_to(candidate)
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    print(build(args.core, args.output, version=args.version, source_revision=args.source_revision))


if __name__ == "__main__":
    main()
