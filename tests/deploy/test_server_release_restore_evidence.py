import io
import tarfile

import pytest

from tools.release import verify_server_release_payload


RELEASE = "endpoint-platform-aabbccddeeff"


def _archive(path, *, unsafe=False):
    with tarfile.open(path, "w:gz") as tar:
        root = tarfile.TarInfo(RELEASE)
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        name = "../outside" if unsafe else "app.py"
        member = tarfile.TarInfo(f"{RELEASE}/{name}")
        member.size = 4
        tar.addfile(member, io.BytesIO(b"code"))


def test_compare_records_exact_bytes_extras_and_changes(tmp_path):
    archive = tmp_path / "source.tar.gz"
    _archive(archive)
    release = tmp_path / RELEASE
    release.mkdir()
    file = release / "app.py"
    file.write_bytes(b"code")
    (release / "venv").symlink_to(tmp_path / "other", target_is_directory=True)

    report = verify_server_release_payload.compare(archive, release)
    assert report["archive_payload_matches"]
    assert report["extra_entries"] == ["venv"]
    assert len(report["archive_sha256"]) == 64
    file.write_bytes(b"diff")
    report = verify_server_release_payload.compare(archive, release)
    assert not report["archive_payload_matches"]
    assert report["mismatches"] == ["app.py"]
    file.unlink()
    file.symlink_to(archive)
    report = verify_server_release_payload.compare(archive, release)
    assert report["mismatches"] == ["app.py"]


def test_unsafe_archive_cannot_supply_evidence(tmp_path):
    archive = tmp_path / "source.tar.gz"
    _archive(archive, unsafe=True)
    release = tmp_path / RELEASE
    release.mkdir()
    with pytest.raises(ValueError, match="unsafe archive member"):
        verify_server_release_payload.compare(archive, release)
