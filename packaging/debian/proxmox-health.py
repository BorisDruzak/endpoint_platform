"""Publish bounded status from local Proxmox read-only interfaces."""

import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time


def query(*args):
    try:
        data = subprocess.check_output(args, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
        if len(data) <= 131_072:
            return data.decode("utf-8")
    except (OSError, subprocess.SubprocessError, UnicodeError):
        pass
    return None


def pve_rows(path, *options):
    raw = query("/usr/bin/pvesh", "get", path, *options, "--output-format", "json")
    try:
        rows = json.loads(raw) if raw is not None else None
    except ValueError:
        return None
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else None


def collect():
    checks = dict.fromkeys(("proxmox_api", "proxmox_quorum", "proxmox_members", "proxmox_storage"), "unknown")
    node = socket.gethostname().split(".", 1)[0]
    http = None
    name = socket.getfqdn()
    if re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", name):
        reply = query(
            "/usr/bin/curl", "--disable", "--noproxy", "*", "--max-time", "6",
            "--silent", "--output", "/dev/null", "--write-out", "%{http_code}",
            "--cacert", "/etc/pve/pve-root-ca.pem", "--resolve", f"{name}:8006:127.0.0.1",
            f"https://{name}:8006/api2/json/version",
        )
        if reply and reply.isascii() and reply.isdigit() and 100 <= int(reply) <= 599:
            http = int(reply)
        checks["proxmox_api"] = "ok" if http in (200, 401) else "failed"

    cluster = pve_rows("/cluster/status")
    if cluster is not None:
        info = next((row for row in cluster if row.get("type") == "cluster"), {})
        if info.get("quorate") in (0, 1):
            checks["proxmox_quorum"] = "ok" if info["quorate"] else "failed"
        members = [row for row in cluster if row.get("type") == "node"]
        if members and type(info.get("nodes")) is int:
            checks["proxmox_members"] = (
                "ok" if len(members) == info["nodes"] and all(row.get("online") == 1 for row in members)
                else "failed"
            )

    resources = pve_rows("/cluster/resources", "--type", "storage")
    storage = []
    if resources is not None:
        for row in resources:
            identifier = row.get("storage")
            if row.get("node") != node or not isinstance(identifier, str) or not re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", identifier):
                continue
            available = row.get("status") == "available"
            entry = {"id": identifier, "available": available}
            total, used = row.get("maxdisk"), row.get("disk")
            if available and type(total) is int and type(used) is int and 0 <= used <= total and total > 0:
                entry.update(total=total, used=used)
            storage.append(entry)
        if storage:
            checks["proxmox_storage"] = "ok" if all(row["available"] for row in storage) else "failed"
    storage.sort(key=lambda row: (
        row["available"], -(row.get("used", 0) / row.get("total", 1)), row["id"],
    ))
    return {
        "schema_version": 1, "sampled_at": int(time.time()), "checks": checks,
        "http_status": http, "storage": storage[:15],
    }


def main():
    directory = Path("/run/endpoint-proxmox-health")
    descriptor, name = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(collect(), stream, separators=(",", ":"))
            os.fchmod(stream.fileno(), 0o644)
        os.replace(name, directory / "status.json")
    finally:
        Path(name).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
