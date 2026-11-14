from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
import hashlib

import pytest

from tools.release import build_ubuntu_apt_repository as apt


@pytest.mark.parametrize("codename", ["noble", "bookworm"])
def test_renewal_keeps_packages_and_signed_index_hashes(tmp_path, monkeypatch, codename):
    suite = tmp_path / "dists" / codename
    index = suite / "main/binary-amd64/Packages"
    index.parent.mkdir(parents=True)
    package = tmp_path / "pool/test.deb"
    package.parent.mkdir()
    artifact = b"immutable package"
    package.write_bytes(artifact)
    packages = (
        f"Filename: pool/test.deb\nSize: {len(artifact)}\n"
        f"SHA256: {hashlib.sha256(artifact).hexdigest()}\n\n"
    ).encode()
    index.write_bytes(packages)
    now = datetime(2026, 11, 14, tzinfo=UTC)
    suffix = (
        f"Codename: {codename}\nSHA256:\n"
        f" {hashlib.sha256(index.read_bytes()).hexdigest()} {index.stat().st_size} main/binary-amd64/Packages\n"
    )
    release = ("Date: " + format_datetime(now - timedelta(days=4)) + "\nValid-Until: "
               + format_datetime(now + timedelta(days=3)) + "\n" + suffix)
    (suite / "InRelease").write_text(release, encoding="utf-8")

    monkeypatch.setattr(apt, "_verified_release", lambda path, keyring, fingerprint: path.read_text())
    monkeypatch.setattr(apt, "_sign_release",
                        lambda release, output, fingerprint: output.write_bytes(release.read_bytes()))
    fingerprint = "a" * 40
    apt.renew(tmp_path, tmp_path / "key.gpg", fingerprint, now=now, codename=codename)
    updated = (suite / "InRelease").read_text()
    assert updated.endswith(suffix)
    assert format_datetime(now + timedelta(days=7), usegmt=True) in updated
    assert package.read_bytes() == artifact
    assert index.read_bytes() == packages
    package.write_bytes(b"corrupt package!")
    with pytest.raises(ValueError, match="pool/test.deb"):
        apt.renew(tmp_path, tmp_path / "key.gpg", fingerprint, now=now + timedelta(days=1), codename=codename)
    assert (suite / "InRelease").read_text() == updated
    package.write_bytes(artifact)
    index.write_bytes(b"changed packages")
    with pytest.raises(ValueError, match="hash"):
        apt.renew(tmp_path, tmp_path / "key.gpg", fingerprint, now=now + timedelta(days=1), codename=codename)
    assert (suite / "InRelease").read_text() == updated
