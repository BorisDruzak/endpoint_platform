"""Request and complete web-approved enrollment for an Ubuntu server."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
from uuid import UUID

import httpx

from tools.provision_alt_test_agent import ENDPOINT_ORIGIN, parse_hardware_fingerprint


PACKAGE = "endpoint-agent-ubuntu"
PACKAGE_VERSION = "3.2.192-1ubuntu1"
PACKAGE_SHA256 = "8affee69264c5cbdc76237ba83dfe5db91ab7a34562ee92f024d9d2b24471a7d"
PACKAGE_197 = "3.2.197-1ubuntu1"
PACKAGE_197_SHA256 = "1d30e147ef8e108a2b379ffffcfb765d66ddb24926974592b23d86e491a6d573"
CA_SHA256 = "5525eccf01536b7f0436d96500c663f7a58edac463f00f0fb34a59dd8b3250be"
STAGE_DIRECTORY = "/run/endpoint-ubuntu-pilot"


@dataclass(frozen=True)
class ServerTarget:
    ssh_host: str
    hostname: str
    address: str
    ca_path: str
    role: str
    package_version: str = PACKAGE_VERSION
    package_sha256: str = PACKAGE_SHA256


TARGETS = {
    "openvpn": ServerTarget("openvpn-100-30", "openvpn", "192.168.100.30",
                            "/etc/apt/keyrings/endpoint-ubuntu-ca.crt", "openvpn"),
    "endpoint": ServerTarget("endpoint-platform-server", "endpointplatform", "192.168.100.19",
                             "/etc/endpoint-platform/sosnadmin-local-ca.crt", "endpoint_platform"),
    "registry": ServerTarget("root@registoryengine", "registoryengine", "192.168.100.12",
                             "/etc/apt/keyrings/endpoint-ubuntu-ca.crt", "registry_engine",
                             PACKAGE_197, PACKAGE_197_SHA256),
    "acti": ServerTarget("acti-v3", "acti-v3", "192.168.100.45",
                         "/etc/apt/keyrings/endpoint-ubuntu-ca.crt", "acti_v3",
                         PACKAGE_197, PACKAGE_197_SHA256),
}


def _ssh(
    command: str, *, host: str, input: bytes | None = None, timeout: int = 120,
    missing_claim_status: int | None = None
) -> bytes:
    try:
        result = subprocess.run(
            ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", host, command],
            input=input,
            stdin=subprocess.DEVNULL if input is None else None,
            capture_output=True,
            timeout=timeout,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        if error.returncode == missing_claim_status:
            raise RuntimeError("Ubuntu server has no staged claim or verified enrollment to resume") from None
        if error.returncode == 4:
            message = error.stdout.decode("ascii", errors="ignore").strip()
            if re.fullmatch(r"Ubuntu enrollment HTTP [1-5][0-9]{2}", message):
                raise RuntimeError(message) from None
        raise RuntimeError("Ubuntu server SSH operation failed") from None
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("Ubuntu server SSH operation failed") from None
    return result.stdout


def _preflight(target: ServerTarget) -> tuple[str, ssl.SSLContext]:
    output = _ssh(f"""set -eu
test "$(hostname -s)" = {target.hostname}
ip -4 -o address show | grep -Fq ' inet {target.address}/'
test "$(dpkg --print-architecture)" = amd64
test "$(. /etc/os-release; printf '%s/%s' "$ID" "$VERSION_ID")" = ubuntu/24.04
sudo -n test ! -e {STAGE_DIRECTORY}
sudo -n test ! -L {STAGE_DIRECTORY}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cd "$tmp"
apt-get download {PACKAGE}={target.package_version} >&2
deb={PACKAGE}_{target.package_version}_amd64.deb
printf '%s  %s\\n' {target.package_sha256} "$deb" | sha256sum -c - >&2
dpkg-deb -x "$deb" unpacked
unpacked/usr/lib/{PACKAGE}/endpoint-agent --print-hardware-fingerprint
""", host=target.ssh_host)
    fingerprint = parse_hardware_fingerprint(output)
    pem = _ssh(f"cat {target.ca_path}", host=target.ssh_host).decode("ascii")
    if hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.strip())).hexdigest() != CA_SHA256:
        raise RuntimeError("Ubuntu server production CA fingerprint mismatch")
    return fingerprint, ssl.create_default_context(cadata=pem)


def finish_installation(target: ServerTarget) -> UUID:
    script = Path(__file__).with_suffix(".sh").read_text(encoding="utf-8")
    output = _ssh(
        f"sudo -n /bin/bash -s -- {target.role}", host=target.ssh_host,
        input=script.encode("utf-8"), timeout=240, missing_claim_status=3
    )
    return UUID(output.decode("ascii").strip())


def web_enrollment(action: str, target: ServerTarget, fingerprint: str | None = None) -> dict:
    script = Path(__file__).with_name("ubuntu_console_enrollment.py").read_text(encoding="utf-8")
    args = (action, target.hostname, fingerprint, target.package_version, target.package_sha256)
    tail = f"\ntry:\n    main(*{args!r})\nexcept RuntimeError as error:\n    import sys\n    print(str(error))\n    sys.exit(4)\n"
    result = _ssh("sudo -n /usr/bin/python3 -", host=target.ssh_host, input=(script + tail).encode("utf-8"))
    status = json.loads(result)
    UUID(status["request_id"])
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, default="openvpn")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--check", action="store_true", help="Run SSH, package and TLS preflight only")
    actions.add_argument("--finish", action="store_true", help="Resume installation after claim staging")
    actions.add_argument("--request", action="store_true", help="Submit this host for approval in Endpoint Console")
    actions.add_argument("--collect", action="store_true", help="Retrieve approval and finish the native installation")
    args = parser.parse_args()
    target = TARGETS[args.target]

    try:
        if args.finish:
            print(f"Installed {target.hostname} agent, device {finish_installation(target)}")
            return 0
        if args.collect:
            status = web_enrollment("collect", target)
            print(f"Request {status['request_id']}: {status['status']}")
            if status["status"] == "claim_staged":
                print(f"Installed {target.hostname} agent, device {finish_installation(target)}")
            return 0
        fingerprint, context = _preflight(target)
        if args.request:
            status = web_enrollment("request", target, fingerprint)
            print(f"Request {status['request_id']}: {status['status']}")
            return 0
        with httpx.Client(
            base_url=ENDPOINT_ORIGIN, verify=context, timeout=15.0, follow_redirects=False, trust_env=False
        ) as client:
            if client.get("/healthz").status_code != 200:
                raise RuntimeError("Endpoint production health check failed")
        print(f"{target.hostname}: SSH, package and production TLS preflight passed")
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (EOFError, OSError, ValueError, httpx.HTTPError):
        print("Ubuntu claim preflight or issuance failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
