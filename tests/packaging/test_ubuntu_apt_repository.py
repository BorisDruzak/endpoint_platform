from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
import hashlib

import pytest

from tools.release import build_ubuntu_apt_repository as apt


def _repository(tmp_path, codename, *, date, expiry):
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
    suffix = (
        f"Codename: {codename}\nSHA256:\n"
        f" {hashlib.sha256(index.read_bytes()).hexdigest()} {index.stat().st_size} main/binary-amd64/Packages\n"
    )
    release = ("Date: " + format_datetime(date) + "\nValid-Until: "
               + format_datetime(expiry) + "\n" + suffix)
    (suite / "InRelease").write_text(release, encoding="utf-8")
    return suite, index, package, artifact, packages, suffix


@pytest.fixture(autouse=True)
def signed_metadata(monkeypatch):
    monkeypatch.setattr(apt, "_verified_release", lambda path, keyring, fingerprint: path.read_text())
    monkeypatch.setattr(apt, "_sign_release",
                        lambda release, output, fingerprint: output.write_bytes(release.read_bytes()))


@pytest.mark.parametrize("codename", ["noble", "bookworm"])
def test_renewal_keeps_packages_and_signed_index_hashes(tmp_path, codename):
    now = datetime(2026, 11, 14, tzinfo=UTC)
    suite, index, package, artifact, packages, suffix = _repository(
        tmp_path, codename, date=now - timedelta(days=4), expiry=now + timedelta(days=3),
    )
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


@pytest.mark.parametrize("codename", ["noble", "bookworm"])
@pytest.mark.parametrize("remaining", [timedelta(days=3), -timedelta(days=1)])
def test_scheduled_renewal_signs_due_repository_once(tmp_path, codename, remaining):
    now = datetime(2026, 11, 14, tzinfo=UTC)
    suite, index, package, artifact, packages, suffix = _repository(
        tmp_path, codename, date=now - timedelta(days=8), expiry=now + remaining,
    )
    fingerprint = "a" * 40
    keyring = tmp_path / "key.gpg"

    assert apt.renew(tmp_path, keyring, fingerprint, now=now, codename=codename, only_if_due=True) == (
        now + timedelta(days=7)
    )
    renewed = (suite / "InRelease").read_bytes()
    assert renewed.decode().endswith(suffix)
    assert apt.renew(
        tmp_path, keyring, fingerprint, now=now + timedelta(days=1), codename=codename, only_if_due=True,
    ) is None
    assert (suite / "InRelease").read_bytes() == renewed
    assert package.read_bytes() == artifact
    assert index.read_bytes() == packages


def test_scheduled_renewal_verifies_fresh_files_without_signing(tmp_path, monkeypatch):
    now = datetime(2026, 11, 14, tzinfo=UTC)
    suite, _, package, *_ = _repository(
        tmp_path, "noble", date=now - timedelta(days=3), expiry=now + timedelta(days=3, seconds=1),
    )

    def unexpected_signing(*args):
        pytest.fail("a fresh repository must not be signed")

    monkeypatch.setattr(apt, "_sign_release", unexpected_signing)
    signed = (suite / "InRelease").read_bytes()
    keyring = tmp_path / "key.gpg"

    assert apt.renew(tmp_path, keyring, "a" * 40, now=now, only_if_due=True) is None
    assert (suite / "InRelease").read_bytes() == signed
    assert not (suite / "Release").exists()

    package.write_bytes(b"corrupt package!")
    with pytest.raises(ValueError, match="pool/test.deb"):
        apt.renew(tmp_path, keyring, "a" * 40, now=now, only_if_due=True)
    assert (suite / "InRelease").read_bytes() == signed


def test_scheduled_renewal_rejects_future_dated_metadata(tmp_path):
    now = datetime(2026, 11, 14, tzinfo=UTC)
    suite, *_ = _repository(
        tmp_path, "noble", date=now + timedelta(minutes=1), expiry=now + timedelta(days=7, minutes=1),
    )
    signed = (suite / "InRelease").read_bytes()

    with pytest.raises(ValueError, match="future"):
        apt.renew(tmp_path, tmp_path / "key.gpg", "a" * 40, now=now, only_if_due=True)
    assert (suite / "InRelease").read_bytes() == signed
