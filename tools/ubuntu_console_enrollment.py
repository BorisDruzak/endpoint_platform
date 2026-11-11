"""Root-side capability handoff for an Ubuntu Console enrollment request."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import UUID, uuid4


ORIGIN = "https://endpoint.sosnadmin.local"
HOST_CA = {
    "dirpost": Path("/etc/apt/keyrings/endpoint-ubuntu-ca.crt"),
    "openvpn": Path("/etc/apt/keyrings/endpoint-ubuntu-ca.crt"),
    "endpointplatform": Path("/etc/endpoint-platform/sosnadmin-local-ca.crt"),
}
CA_DIGEST = "5525eccf01536b7f0436d96500c663f7a58edac463f00f0fb34a59dd8b3250be"
PROOF = Path("/var/cache/endpoint-ubuntu-pilot-request")
STAGE = Path("/run/endpoint-ubuntu-pilot")
FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
CLAIM = re.compile(r"ic_[0-9a-f]{32}\.[A-Za-z0-9_-]{43}")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def private_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("Ubuntu enrollment storage is not protected")


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="ascii") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("Ubuntu enrollment input is not protected")
        return handle.read(8192)


def atomic_write(path, value):
    scratch = path.with_name("." + path.name + "." + uuid4().hex)
    try:
        with scratch.open("x", encoding="ascii") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(scratch, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        scratch.unlink(missing_ok=True)


def post(ca, path, body):
    pem = ca.read_text(encoding="ascii")
    if hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.strip())).hexdigest() != CA_DIGEST:
        raise RuntimeError("Ubuntu enrollment CA changed")
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cadata=pem)), NoRedirect())
    request = Request(ORIGIN + path, data=json.dumps(body).encode("ascii"),
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener.open(request, timeout=15) as response:
            return json.loads(response.read(16384))
    except HTTPError as error:
        raise RuntimeError(f"Ubuntu enrollment HTTP {error.code}") from None


def main(action, expected_hostname, fingerprint=None, version=None, digest=None):
    if os.geteuid() != 0:
        raise RuntimeError("Ubuntu enrollment requires root")
    os.umask(0o077)
    hostname = socket.gethostname().split(".", 1)[0]
    if hostname != expected_hostname or hostname not in HOST_CA:
        raise RuntimeError("Unexpected Ubuntu pilot host")
    ca = HOST_CA[hostname]
    private_directory(PROOF)
    proof_file = PROOF / "request.json"
    fd = os.open(PROOF / "lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == "request" and not proof_file.exists():
            if not FINGERPRINT.fullmatch(fingerprint):
                raise RuntimeError("Ubuntu fingerprint is invalid")
            atomic_write(proof_file, json.dumps({
                "schema_version": "ubuntu_deb_enrollment_request_v1", "hostname": hostname,
                "package_version": version, "package_sha256": digest, "installation_id": str(uuid4()),
                "request_capability": secrets.token_urlsafe(32), "hardware_fingerprint": fingerprint,
            }))
        body = json.loads(private_read(proof_file))
        if action == "request":
            if body["hardware_fingerprint"] != fingerprint or body["package_version"] != version or body["package_sha256"] != digest:
                raise RuntimeError("Existing Ubuntu request belongs to different installation inputs")
            status = post(ca, "/api/v1/enrollment/ubuntu/requests", body)
            request_id = str(UUID(status["request_id"]))
            atomic_write(PROOF / "id", request_id)
        else:
            request_id = str(UUID(private_read(PROOF / "id")))
            base = f"/api/v1/enrollment/linux/requests/{request_id}"
            status = post(ca, base + "/status", {"request_capability": body["request_capability"]})
            if status["status"] in {"approved", "claim_issued"}:
                delivery = post(ca, base + "/claim", {key: body[key] for key in (
                    "request_capability", "installation_id", "hardware_fingerprint"
                )})
                claim = delivery["claim"]
                if not CLAIM.fullmatch(claim):
                    raise RuntimeError("Ubuntu enrollment claim is invalid")
                private_directory(STAGE)
                for name, value in (("installation-id", body["installation_id"]), ("claim", claim)):
                    destination = STAGE / name
                    if destination.exists():
                        previous = private_read(destination)
                        if previous not in {value, value + "\n"}:
                            raise RuntimeError("A different Ubuntu claim is already staged")
                        if previous != value:
                            atomic_write(destination, value)
                    else:
                        atomic_write(destination, value)
                status["status"] = "claim_staged"
        print(json.dumps({"request_id": request_id, "status": status["status"]}))
