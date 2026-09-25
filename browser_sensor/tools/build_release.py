"""Build and verify the signed Browser Sensor release artifact."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_MAX_CRX_BYTES = 25 * 1024 * 1024
_MAX_HEADER_BYTES = 1024 * 1024
_MAX_PAYLOAD_BYTES = 20 * 1024 * 1024
_SOURCE_FILES = ("manifest.json", "background.js", "content.js", "protocol.js")
UPDATE_URL = "https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml"
_CRX_URL_PREFIX = "https://endpoint.sosnadmin.local/api/v1/browser-sensor/releases"


def render_update_xml(extension_id: str, version: str) -> bytes:
    """Render the exact self-hosted update document accepted at publication."""
    crx_url = f"{_CRX_URL_PREFIX}/{version}/sensor.crx"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">\n'
        f'  <app appid="{extension_id}"><updatecheck codebase="{crx_url}" version="{version}"/></app>\n'
        "</gupdate>\n"
    ).encode("utf-8")


def extension_id_from_public_key(public_key_der: bytes) -> str:
    """Return Chromium's 32-character ID for a DER SPKI public key."""
    prefix = hashlib.sha256(public_key_der).digest()[:16]
    return "".join(
        chr(ord("a") + nibble) for byte in prefix for nibble in (byte >> 4, byte & 15)
    )


def load_signing_identity(
    key_path: Path, repository_root: Path, pinned_id: str
) -> tuple[str, bytes]:
    """Check an externally stored RSA key against the committed extension ID."""
    resolved_key = key_path.resolve(strict=True)
    if resolved_key.is_relative_to(repository_root.resolve()):
        raise ValueError("signing key must be outside the repository")
    try:
        private_key = serialization.load_pem_private_key(
            resolved_key.read_bytes(), password=None
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid RSA signing key") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("signing key must be RSA")
    if (
        private_key.key_size < 2048
        or private_key.public_key().public_numbers().e != 65537
    ):
        raise ValueError("signing key must be RSA-2048+ with exponent 65537")
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    extension_id = extension_id_from_public_key(public_der)
    if extension_id != pinned_id:
        raise ValueError("signing key does not match pinned extension ID")
    return extension_id, public_der


def _read_varint(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if position >= len(data):
            raise ValueError("truncated CRX header")
        byte = data[position]
        position += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, position
    raise ValueError("invalid CRX header varint")


def _byte_fields(data: bytes) -> list[tuple[int, bytes]]:
    fields: list[tuple[int, bytes]] = []
    position = 0
    while position < len(data):
        tag, position = _read_varint(data, position)
        if tag == 0 or tag & 7 != 2:
            raise ValueError("unsupported CRX header field")
        size, position = _read_varint(data, position)
        if size > len(data) - position:
            raise ValueError("truncated CRX header field")
        fields.append((tag >> 3, data[position : position + size]))
        position += size
    return fields


def verify_crx(
    path: Path,
    expected_public_der: bytes,
    expected_id: str,
    expected_files: set[str],
) -> dict[str, bytes]:
    """Verify a CRX3 RSA proof and its exact browser-extension payload."""
    if path.stat().st_size > _MAX_CRX_BYTES:
        raise ValueError("CRX exceeds size limit")
    crx = path.read_bytes()
    if len(crx) < 12 or crx[:4] != b"Cr24" or int.from_bytes(crx[4:8], "little") != 3:
        raise ValueError("expected CRX3 package")
    header_size = int.from_bytes(crx[8:12], "little")
    if header_size > _MAX_HEADER_BYTES or 12 + header_size >= len(crx):
        raise ValueError("invalid CRX header size")
    fields = _byte_fields(crx[12 : 12 + header_size])
    signed_headers = [value for number, value in fields if number == 10000]
    if len(signed_headers) != 1:
        raise ValueError("CRX signed header missing or duplicated")
    signed_header = signed_headers[0]
    signed_data = _byte_fields(signed_header)
    crx_ids = [value for number, value in signed_data if number == 1]
    if (
        len(crx_ids) != 1
        or crx_ids[0] != hashlib.sha256(expected_public_der).digest()[:16]
    ):
        raise ValueError("CRX ID does not match signing identity")
    if extension_id_from_public_key(expected_public_der) != expected_id:
        raise ValueError("CRX extension ID differs from pinned ID")
    proofs = [_byte_fields(value) for number, value in fields if number == 2]
    matching_proofs = [
        proof
        for proof in proofs
        if [value for number, value in proof if number == 1] == [expected_public_der]
    ]
    if len(matching_proofs) != 1:
        raise ValueError("CRX public key differs from signing identity")
    signatures = [value for number, value in matching_proofs[0] if number == 2]
    if len(signatures) != 1:
        raise ValueError("CRX RSA signature missing or duplicated")
    archive = crx[12 + header_size :]
    signed_message = (
        b"CRX3 SignedData\x00"
        + len(signed_header).to_bytes(4, "little")
        + signed_header
        + archive
    )
    key = serialization.load_der_public_key(expected_public_der)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("CRX public key must be RSA")
    try:
        key.verify(
            signatures[0],
            signed_message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("CRX signature verification failed") from exc

    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            entries = package.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(expected_files) or set(names) != expected_files:
                raise ValueError("CRX packaged files differ from approved source")
            if sum(entry.file_size for entry in entries) > _MAX_PAYLOAD_BYTES:
                raise ValueError("CRX payload exceeds size limit")
            result = {name: package.read(name) for name in names}
    except zipfile.BadZipFile as exc:
        raise ValueError("invalid CRX ZIP payload") from exc
    return result


def verify_crx_for_extension_id(
    path: Path, expected_id: str, expected_files: set[str]
) -> dict[str, bytes]:
    """Verify a published CRX without access to its private signing key."""
    if path.stat().st_size > _MAX_CRX_BYTES:
        raise ValueError("CRX exceeds size limit")
    crx = path.read_bytes()
    if len(crx) < 12 or crx[:4] != b"Cr24" or int.from_bytes(crx[4:8], "little") != 3:
        raise ValueError("expected CRX3 package")
    header_size = int.from_bytes(crx[8:12], "little")
    if header_size > _MAX_HEADER_BYTES or 12 + header_size >= len(crx):
        raise ValueError("invalid CRX header size")
    public_keys = [
        value
        for number, proof in _byte_fields(crx[12 : 12 + header_size])
        if number == 2
        for field, value in _byte_fields(proof)
        if field == 1 and extension_id_from_public_key(value) == expected_id
    ]
    if len(public_keys) != 1:
        raise ValueError("CRX signing identity does not match pinned extension ID")
    return verify_crx(path, public_keys[0], expected_id, expected_files)


def build_release(
    source_dir: Path,
    key_path: Path,
    chrome_path: Path,
    output_dir: Path,
    source_revision: str,
    minimum_agent_version: str,
) -> dict[str, str | int]:
    """Use Chrome's packer, verify its CRX3 proof, then publish immutable files."""
    if not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise ValueError("source revision must be a full commit SHA")
    if not re.fullmatch(r"\d+\.\d+\.\d+", minimum_agent_version):
        raise ValueError("minimum Agent version must be major.minor.patch")
    pinned_id = (source_dir / "extension-id.txt").read_text(encoding="ascii").strip()
    extension_id, public_der = load_signing_identity(
        key_path, source_dir.parent, pinned_id
    )
    source_manifest = json.loads(
        (source_dir / "manifest.json").read_text(encoding="utf-8")
    )
    version = source_manifest["version"]
    if not isinstance(version, str) or not re.fullmatch(r"\d+(?:\.\d+){1,3}", version):
        raise ValueError("invalid extension version")
    if "key" in source_manifest or "update_url" in source_manifest:
        raise ValueError("source manifest must not contain release identity or URL")
    release_dir = output_dir / version
    if release_dir.exists():
        raise ValueError("release version already exists")
    if not chrome_path.is_file():
        raise ValueError("Chrome packer is unavailable")

    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="browser-release-", dir=output_dir
    ) as temp_name:
        temp = Path(temp_name)
        stage = temp / "sensor"
        stage.mkdir()
        manifest = dict(source_manifest, update_url=UPDATE_URL)
        manifest_bytes = (
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        (stage / "manifest.json").write_bytes(manifest_bytes)
        for name in _SOURCE_FILES[1:]:
            shutil.copyfile(source_dir / name, stage / name)
        command = [
            str(chrome_path),
            "--no-first-run",
            f"--user-data-dir={temp / 'chrome-profile'}",
            f"--pack-extension={stage}",
            f"--pack-extension-key={key_path.resolve(strict=True)}",
        ]
        try:
            packed = subprocess.run(
                command, capture_output=True, timeout=120, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError("Chrome packer timed out") from exc
        crx_path = temp / "sensor.crx"
        if packed.returncode != 0 or not crx_path.is_file():
            raise ValueError("Chrome did not produce a signed CRX")
        verified = verify_crx(crx_path, public_der, extension_id, set(_SOURCE_FILES))
        if verified["manifest.json"] != manifest_bytes or any(
            verified[name] != (source_dir / name).read_bytes()
            for name in _SOURCE_FILES[1:]
        ):
            raise ValueError("CRX content differs from approved source")

        artifact_name = "sensor.crx"
        update_xml = render_update_xml(extension_id, version)
        metadata: dict[str, str | int] = {
            "schema_version": "browser_sensor_release_v1",
            "extension_version": version,
            "extension_id": extension_id,
            "protocol_version": 1,
            "source_revision": source_revision,
            "artifact_filename": artifact_name,
            "artifact_sha256": hashlib.sha256(crx_path.read_bytes()).hexdigest(),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "update_manifest_sha256": hashlib.sha256(update_xml).hexdigest(),
            "minimum_agent_version": minimum_agent_version,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        candidate = temp / "release"
        candidate.mkdir()
        shutil.copyfile(crx_path, candidate / artifact_name)
        (candidate / "update.xml").write_bytes(update_xml)
        (candidate / "release.json").write_text(
            json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        if release_dir.exists():
            raise ValueError("release version already exists")
        candidate.rename(release_dir)
    return metadata


def _committed_revision(source_dir: Path) -> str:
    repo = source_dir.parent
    try:
        status = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "--", source_dir.name],
            capture_output=True,
            text=True,
            check=True,
        )
        revision = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("Browser Sensor source requires a Git commit") from exc
    if status.stdout.strip():
        raise ValueError("Browser Sensor source has uncommitted changes")
    return revision.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a signed Endpoint Browser Sensor CRX"
    )
    parser.add_argument(
        "--source-dir", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--key-path", type=Path, required=True)
    parser.add_argument("--chrome-path", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--minimum-agent-version", required=True)
    args = parser.parse_args(argv)
    metadata = build_release(
        source_dir=args.source_dir,
        key_path=args.key_path,
        chrome_path=args.chrome_path,
        output_dir=args.output_dir,
        source_revision=_committed_revision(args.source_dir),
        minimum_agent_version=args.minimum_agent_version,
    )
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        raise SystemExit(f"release build failed: {exc}") from exc
