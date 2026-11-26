"""Bind ALT RPM headers and payloads across the existing signing step."""

import hashlib
import os
from pathlib import Path
import re
import struct

from tools.release.linux_native_verifier import MAX_RPM, _json


HEADER = struct.Struct(">8sII")
HEADER_MAGIC = b"\x8e\xad\xe8\x01\0\0\0\0"
LEAD_SIZE = 96
SHA256 = re.compile(r"[0-9a-f]{64}")


def _header_end(stream, size):
    raw = stream.read(HEADER.size)
    if len(raw) != HEADER.size:
        raise ValueError("Truncated ALT RPM header")
    magic, entries, data_bytes = HEADER.unpack(raw)
    end = stream.tell() + entries * 16 + data_bytes
    if magic != HEADER_MAGIC or not entries or end >= size:
        raise ValueError("Invalid ALT RPM header")
    return end


def signing_content_sha256(path: Path) -> str:
    """Hash the RPM lead, main header and payload, excluding the signature envelope."""
    with path.open("rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        lead = stream.read(LEAD_SIZE)
        if not 0 < size <= MAX_RPM or len(lead) != LEAD_SIZE or lead[:4] != b"\xed\xab\xee\xdb":
            raise ValueError("Invalid ALT RPM lead or size")
        # RPM v4 pads only the signature header to an eight-byte boundary.
        body = (_header_end(stream, size) + 7) & ~7
        stream.seek(body)
        _header_end(stream, size)
        stream.seek(body)
        digest = hashlib.sha256(lead)
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()


def verify_build_receipt(raw: bytes, candidate: dict, signed_rpms: tuple[Path, Path]) -> None:
    receipt = _json(raw)
    expected = {
        "schema_version": 1, "state": "built", "platform": "alt", "artifact": "alt_native_rpm",
        **{key: candidate[key] for key in ("request_id", "version", "build_revision")},
        "alt_native": {
            "frozen_manifest_sha256": candidate["frozen_manifest_sha256"],
            "setup_sha256": candidate["members"]["endpoint-agent-setup"]["sha256"],
        },
    }
    if (not isinstance(receipt, dict) or type(receipt.get("schema_version")) is not int
            or any(receipt.get(key) != value for key, value in expected.items())):
        raise ValueError("ALT build receipt differs from the bound candidate")
    outputs = receipt.get("outputs")
    if not isinstance(outputs, list) or len(outputs) != len(signed_rpms):
        raise ValueError("ALT build receipt needs the exact RPM pair")
    for rpm in signed_rpms:
        matches = [value for value in outputs if isinstance(value, dict) and value.get("filename") == rpm.name]
        if len(matches) != 1:
            raise ValueError("ALT build receipt needs the exact RPM pair")
        record = matches[0]
        digest = record.get("sha256")
        if (record.get("path") != rpm.name or type(record.get("size")) is not int
                or not 0 < record["size"] <= MAX_RPM or not isinstance(digest, str) or not SHA256.fullmatch(digest)
                or record.get("signing_content_sha256") != signing_content_sha256(rpm)):
            raise ValueError(f"Signed ALT RPM header or payload differs from the build receipt: {rpm.name}")
