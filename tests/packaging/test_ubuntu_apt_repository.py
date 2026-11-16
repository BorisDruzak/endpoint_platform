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


@pytest.fixture
def renewal_for_publication(tmp_path, codename):
    now = datetime(2026, 11, 14, tzinfo=UTC)
    root = tmp_path / "live"
    suite, index, package, artifact, packages, _ = _repository(
        root, codename, date=now - timedelta(days=4), expiry=now + timedelta(days=3),
    )
    current = suite / "InRelease"
    (suite / "Release").write_bytes(current.read_bytes())
    staged = tmp_path / "staged"
    staged_suite, *_ = _repository(
        staged, codename, date=now - timedelta(days=4), expiry=now + timedelta(days=3),
    )
    keyring = tmp_path / "key.gpg"
    fingerprint = "a" * 40
    apt.renew(staged, keyring, fingerprint, now=now, codename=codename)
    return root, current, staged_suite / "InRelease", index, package, artifact, packages, now, keyring, fingerprint


@pytest.mark.parametrize("codename", ["noble", "bookworm"])
def test_publish_renewal_replaces_only_metadata(renewal_for_publication, codename):
    root, current, candidate, index, package, artifact, packages, now, keyring, fingerprint = renewal_for_publication
    expected = hashlib.sha256(current.read_bytes()).hexdigest()

    assert apt.publish_renewal(
        root, candidate, expected, keyring, fingerprint, codename=codename, now=now,
    ) == now + timedelta(days=7)
    assert current.read_bytes() == candidate.read_bytes()
    assert current.with_name("Release").read_bytes() == candidate.read_bytes()
    assert index.read_bytes() == packages
    assert package.read_bytes() == artifact


@pytest.mark.parametrize("codename", ["noble", "bookworm"])
def test_publish_renewal_requires_explicit_successor_for_new_signer(renewal_for_publication, codename, monkeypatch):
    root, current, candidate, index, package, artifact, packages, now, keyring, original_fingerprint = (
        renewal_for_publication
    )
    original = current.read_bytes()
    expected = hashlib.sha256(original).hexdigest()
    successor = "b" * 40

    def verified_release(path, _keyring, fingerprint):
        required = original_fingerprint if path.name == "Original" else successor
        if fingerprint != required:
            raise ValueError("unexpected signer")
        return path.read_text()

    monkeypatch.setattr(apt, "_verified_release", verified_release)
    with pytest.raises(ValueError, match="unexpected signer"):
        apt.publish_renewal(root, candidate, expected, keyring, original_fingerprint, codename=codename, now=now)
    assert current.read_bytes() == current.with_name("Release").read_bytes() == original

    assert apt.publish_renewal(
        root, candidate, expected, keyring, original_fingerprint, codename=codename, now=now,
        successor_fingerprint=successor,
    ) == now + timedelta(days=7)
    assert current.read_bytes() == candidate.read_bytes()
    assert index.read_bytes() == packages
    assert package.read_bytes() == artifact


@pytest.mark.parametrize("codename", ["noble"])
@pytest.mark.parametrize("problem, message", [
    ("stale", "live InRelease changed"),
    ("different_metadata", "only Date and Valid-Until"),
    ("corrupt_payload", "pool/test.deb"),
    ("future", "renewal dates"),
    ("wrong_signer", "signer"),
])
def test_publish_renewal_preserves_live_metadata_on_rejection(
    renewal_for_publication, codename, problem, message, monkeypatch,
):
    root, current, candidate, _, package, _, _, now, keyring, fingerprint = renewal_for_publication
    expected = hashlib.sha256(current.read_bytes()).hexdigest()
    if problem == "stale":
        current.write_bytes(current.read_bytes() + b"\n")
    elif problem == "different_metadata":
        candidate.write_bytes(candidate.read_bytes() + b"Origin: Changed\n")
    elif problem == "corrupt_payload":
        package.write_bytes(b"changed bytes")
    elif problem == "future":
        now -= timedelta(minutes=1)
    else:
        candidate.write_bytes(b"unexpected signature")

        def reject_foreign_signer(path, _keyring, _fingerprint):
            value = path.read_text()
            if value == "unexpected signature":
                raise ValueError("InRelease signer does not match")
            return value

        monkeypatch.setattr(apt, "_verified_release", reject_foreign_signer)
    original = current.read_bytes()
    release = current.with_name("Release")
    original_release = release.read_bytes()

    with pytest.raises(ValueError, match=message):
        apt.publish_renewal(root, candidate, expected, keyring, fingerprint, codename=codename, now=now)
    assert current.read_bytes() == original
    assert release.read_bytes() == original_release


@pytest.mark.parametrize("codename", ["noble"])
def test_publish_renewal_rechecks_live_hash_at_commit(renewal_for_publication, codename, monkeypatch):
    root, current, candidate, _, _, _, _, now, keyring, fingerprint = renewal_for_publication
    original = current.read_bytes()
    expected = hashlib.sha256(original).hexdigest()
    replacement = original + b"other publisher\n"
    verify = apt._verify_indexes

    def replace_live_after_verification(*args):
        verify(*args)
        current.write_bytes(replacement)

    monkeypatch.setattr(apt, "_verify_indexes", replace_live_after_verification)
    with pytest.raises(ValueError, match="live InRelease changed"):
        apt.publish_renewal(root, candidate, expected, keyring, fingerprint, codename=codename, now=now)
    assert current.read_bytes() == replacement
    assert current.with_name("Release").read_bytes() == original


@pytest.mark.parametrize("codename", ["noble", "bookworm"])
def test_prepare_renewal_exports_candidate_without_changing_source(renewal_for_publication, codename, tmp_path):
    root, current, _, _, _, _, _, now, keyring, fingerprint = renewal_for_publication
    original = current.read_bytes()
    output = tmp_path / "outgoing"
    sha = hashlib.sha256(original).hexdigest()
    expected = output / codename / sha / "InRelease"

    assert apt.prepare_renewal(root, output, keyring, fingerprint, now=now, codename=codename) == expected
    prepared = expected.read_bytes()
    assert format_datetime(now + timedelta(days=7), usegmt=True).encode() in prepared
    assert apt.prepare_renewal(
        root, output, keyring, fingerprint, now=now + timedelta(days=1), codename=codename,
    ) == expected
    assert expected.read_bytes() == prepared
    assert current.read_bytes() == original
    assert current.with_name("Release").read_bytes() == original


@pytest.mark.parametrize("codename", ["noble"])
def test_prepare_renewal_does_not_create_output_when_fresh(renewal_for_publication, codename, tmp_path):
    root, current, _, _, _, _, _, now, keyring, fingerprint = renewal_for_publication
    original = current.read_bytes()
    output = tmp_path / "outgoing"

    assert apt.prepare_renewal(
        root, output, keyring, fingerprint, now=now - timedelta(seconds=1), codename=codename,
    ) is None
    assert not output.exists()
    assert current.read_bytes() == original
