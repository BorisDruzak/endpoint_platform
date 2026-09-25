from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import zipfile
from xml.etree import ElementTree

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from browser_sensor.tools.build_release import (
    UPDATE_URL,
    build_release,
    extension_id_from_public_key,
    load_signing_identity,
    main,
    verify_crx,
)


def test_extension_id_uses_chromium_public_key_hash_mapping() -> None:
    assert (
        extension_id_from_public_key(b"public-key-der-fixture")
        == "efhhpkfidpladbiehgdkoaoaepipcpoh"
    )


def _key_file(path: Path) -> tuple[Path, bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_path = path / "signing.pem"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    expected_id = "".join(
        chr(ord("a") + int(nibble, 16))
        for nibble in hashlib.sha256(public_der).hexdigest()[:32]
    )
    return key_path, public_der, expected_id


def test_signing_identity_matches_pinned_id_without_exposing_private_key(
    tmp_path: Path,
) -> None:
    key_path, public_der, expected_id = _key_file(tmp_path)

    assert load_signing_identity(key_path, tmp_path / "repo", expected_id) == (
        expected_id,
        public_der,
    )


def test_signing_identity_rejects_key_in_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    key_path, _, expected_id = _key_file(repo)

    with pytest.raises(ValueError, match="outside the repository"):
        load_signing_identity(key_path, repo, expected_id)


def test_signing_identity_rejects_unexpected_extension_id(tmp_path: Path) -> None:
    key_path, _, _ = _key_file(tmp_path)

    with pytest.raises(ValueError, match="extension ID"):
        load_signing_identity(key_path, tmp_path / "repo", "a" * 32)


def _varint(value: int) -> bytes:
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def _bytes_field(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def _signed_crx(files: dict[str, bytes]) -> tuple[bytes, bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(public_der).digest()
    extension_id = "".join(
        chr(ord("a") + int(nibble, 16)) for nibble in digest.hex()[:32]
    )
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as package:
        for name, body in files.items():
            package.writestr(name, body)
    signed_header = _bytes_field(1, digest[:16])
    message = (
        b"CRX3 SignedData\x00"
        + len(signed_header).to_bytes(4, "little")
        + signed_header
        + archive.getvalue()
    )
    signature = key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    proof = _bytes_field(1, public_der) + _bytes_field(2, signature)
    header = _bytes_field(2, proof) + _bytes_field(10000, signed_header)
    crx = (
        b"Cr24"
        + (3).to_bytes(4, "little")
        + len(header).to_bytes(4, "little")
        + header
        + archive.getvalue()
    )
    return crx, public_der, extension_id


def test_crx_verifier_checks_signature_identity_and_exact_payload(
    tmp_path: Path,
) -> None:
    files = {"manifest.json": b"{}", "background.js": b"safe"}
    crx, public_der, extension_id = _signed_crx(files)
    path = tmp_path / "sensor.crx"
    path.write_bytes(crx)

    assert verify_crx(path, public_der, extension_id, set(files)) == files

    path.write_bytes(crx[:-1] + bytes([crx[-1] ^ 1]))
    with pytest.raises(ValueError, match="signature"):
        verify_crx(path, public_der, extension_id, set(files))


def test_crx_verifier_rejects_extra_packaged_file(tmp_path: Path) -> None:
    crx, public_der, extension_id = _signed_crx(
        {"manifest.json": b"{}", "unapproved.txt": b"secret"}
    )
    path = tmp_path / "sensor.crx"
    path.write_bytes(crx)

    with pytest.raises(ValueError, match="packaged files"):
        verify_crx(path, public_der, extension_id, {"manifest.json"})


def test_real_chrome_release_contains_only_approved_files_and_update_url(
    tmp_path: Path,
) -> None:
    chrome = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    if not chrome.is_file():
        pytest.skip("Chrome packer is not installed on this test host")
    source = tmp_path / "repo" / "browser_sensor"
    source.mkdir(parents=True)
    for name in ("manifest.json", "background.js", "content.js", "protocol.js"):
        shutil.copyfile(
            Path(__file__).parents[2] / "browser_sensor" / name, source / name
        )
    key_path, public_der, extension_id = _key_file(tmp_path)
    (source / "extension-id.txt").write_text(extension_id + "\n", encoding="ascii")
    output_dir = tmp_path / "out"

    metadata = build_release(
        source_dir=source,
        key_path=key_path,
        chrome_path=chrome,
        output_dir=output_dir,
        source_revision="a" * 40,
        minimum_agent_version="3.2.68",
    )

    assert metadata["extension_id"] == extension_id
    assert metadata["source_revision"] == "a" * 40
    assert metadata["minimum_agent_version"] == "3.2.68"
    release_dir = output_dir / "0.1.0"
    assert set(path.name for path in release_dir.iterdir()) == {
        "sensor.crx",
        "update.xml",
        "release.json",
    }
    assert metadata == json.loads(
        (release_dir / "release.json").read_text(encoding="utf-8")
    )
    assert (
        metadata["artifact_sha256"]
        == hashlib.sha256((release_dir / "sensor.crx").read_bytes()).hexdigest()
    )
    files = verify_crx(
        release_dir / "sensor.crx",
        public_der,
        extension_id,
        {"manifest.json", "background.js", "content.js", "protocol.js"},
    )
    assert json.loads(files["manifest.json"])["update_url"] == UPDATE_URL
    xml = ElementTree.fromstring((release_dir / "update.xml").read_bytes())
    namespace = {"g": "http://www.google.com/update2/response"}
    assert xml.find("g:app", namespace).attrib["appid"] == extension_id
    assert xml.find("g:app/g:updatecheck", namespace).attrib["version"] == "0.1.0"

    with pytest.raises(ValueError, match="already exists"):
        build_release(source, key_path, chrome, output_dir, "a" * 40, "3.2.68")


def test_release_cli_uses_clean_committed_source_revision(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    chrome = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    if not chrome.is_file():
        pytest.skip("Chrome packer is not installed on this test host")
    repo = tmp_path / "repo"
    source = repo / "browser_sensor"
    source.mkdir(parents=True)
    for name in ("manifest.json", "background.js", "content.js", "protocol.js"):
        shutil.copyfile(
            Path(__file__).parents[2] / "browser_sensor" / name, source / name
        )
    key_path, _, extension_id = _key_file(tmp_path)
    (source / "extension-id.txt").write_text(extension_id + "\n", encoding="ascii")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Release Test"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "release@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "add", "browser_sensor"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "test: fixture"], check=True
    )
    revision = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()

    assert (
        main(
            [
                "--source-dir",
                str(source),
                "--key-path",
                str(key_path),
                "--chrome-path",
                str(chrome),
                "--output-dir",
                str(tmp_path / "out"),
                "--minimum-agent-version",
                "3.2.68",
            ]
        )
        == 0
    )
    assert (
        json.loads((tmp_path / "out" / "0.1.0" / "release.json").read_text())[
            "source_revision"
        ]
        == revision
    )
    assert extension_id in capsys.readouterr().out

    (source / "background.js").write_text("modified", encoding="utf-8")
    with pytest.raises(ValueError, match="uncommitted"):
        main(
            [
                "--source-dir",
                str(source),
                "--key-path",
                str(key_path),
                "--chrome-path",
                str(chrome),
                "--output-dir",
                str(tmp_path / "other"),
                "--minimum-agent-version",
                "3.2.68",
            ]
        )
