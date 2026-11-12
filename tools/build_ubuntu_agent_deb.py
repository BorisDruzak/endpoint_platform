"""Package the frozen Endpoint Core on its target amd64 Linux distribution."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "endpoint-agent-ubuntu"
CORE_EXECUTABLE = "endpoint-agent"
VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")
RELEASE_REVISION = re.compile(r"[a-f0-9]{40}")


@dataclass(frozen=True)
class DebTarget:
    distro: str
    distro_version: str
    package: str
    revision: str
    glibc: str
    label: str
    conflicts: str = ""

    def render(self, template: Path) -> bytes:
        contents = template.read_bytes().replace(b"\r\n", b"\n")
        agent_label = f"{self.label.removesuffix(' Server')} Agent"
        return contents.replace(PACKAGE.encode(), self.package.encode()).replace(
            b"Ubuntu Server", self.label.encode(),
        ).replace(b"Ubuntu Agent", agent_label.encode())


TARGETS = {
    "ubuntu": DebTarget("ubuntu", "24.04", PACKAGE, "1ubuntu1", "2.39", "Ubuntu Server"),
    "debian12": DebTarget(
        "debian", "12", "endpoint-agent-debian", "1deb12u1", "2.36", "Debian Server",
        conflicts=PACKAGE,
    ),
}


def build(
    core: Path, output: Path, *, version: str, source_revision: str, target: str = "ubuntu",
) -> Path:
    profile = TARGETS[target]
    package = profile.package
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("agent DEB packages must be built on Linux x86_64")
    release = platform.freedesktop_os_release()
    if (release.get("ID"), release.get("VERSION_ID")) != (profile.distro, profile.distro_version):
        raise ValueError(f"{profile.label} packages require a {profile.distro} {profile.distro_version} build host")
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

    package_version = f"{version}-{profile.revision}"
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / f"{package}_{package_version}_amd64.deb"
    if artifact.exists():
        raise FileExistsError(artifact)
    packaging = ROOT / "packaging" / "ubuntu"
    with tempfile.TemporaryDirectory(prefix=f"{package}-", dir=output) as temporary:
        scratch = Path(temporary)
        tree = scratch / "package"
        runtime = tree / "usr" / "lib" / package
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
            ("endpoint-agent-ubuntu.service", f"usr/lib/systemd/system/{package}.service"),
            ("sysusers.conf", f"usr/lib/sysusers.d/{package}.conf"),
            ("tmpfiles.conf", f"usr/lib/tmpfiles.d/{package}.conf"),
            ("agent.conf", f"etc/{package}/agent.conf"),
        ):
            path = tree / destination
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(profile.render(packaging / source))
            path.chmod(0o644)
        metadata = tree / "DEBIAN"
        metadata.mkdir()
        (metadata / "conffiles").write_text(f"/etc/{package}/agent.conf\n", encoding="ascii")
        installed_bytes = sum(
            path.lstat().st_size for path in tree.rglob("*") if not path.is_symlink()
        )
        conflicts = f"Conflicts: {profile.conflicts}\n" if profile.conflicts else ""
        (metadata / "control").write_text(
            f"Package: {package}\n"
            f"Version: {package_version}\n"
            "Section: admin\n"
            "Priority: optional\n"
            "Architecture: amd64\n"
            "Maintainer: Endpoint Platform\n"
            f"Depends: libc6 (>= {profile.glibc}), systemd, init-system-helpers, iproute2, util-linux\n"
            f"{conflicts}"
            f"Installed-Size: {(installed_bytes + 1023) // 1024}\n"
            f"Description: Endpoint Platform agent for {profile.label}\n"
            " Collects host and server-role context through the Endpoint Gateway.\n",
            encoding="ascii",
        )
        for name in ("postinst", "prerm", "postrm"):
            script = metadata / name
            script.write_bytes(profile.render(packaging / name))
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
    parser.add_argument("--target", choices=TARGETS, default="ubuntu")
    args = parser.parse_args()
    print(build(
        args.core, args.output, version=args.version, source_revision=args.source_revision, target=args.target,
    ))


if __name__ == "__main__":
    main()
