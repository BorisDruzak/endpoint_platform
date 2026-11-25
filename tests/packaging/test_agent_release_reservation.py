"""Exercise reservation through the CLI and a real shared Git remote."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest


CLI = Path(__file__).resolve().parents[2] / "tools/release/agent_release.py"
LEDGER = "refs/heads/codex/agent-release-reservations"


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True,
    ).stdout.strip()


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def release_inputs(tmp_path):
    repo, remote = tmp_path / "work", tmp_path / "shared.git"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Release Test")
    git(repo, "config", "user.email", "release@example.invalid")
    release = repo / "docs/releases/windows-3.2.274-candidate.json"
    release.parent.mkdir(parents=True)
    write(release, {"version": "3.2.274"})
    version = repo / "pc_agent/version.py"
    version.parent.mkdir()
    version.write_text('AGENT_VERSION = "3.2.205"\n', encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "test: seed the release checkout")
    git(tmp_path, "init", "--bare", str(remote))
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "origin", "main")
    observed_at = datetime.now(timezone.utc).isoformat()
    snapshot = {
        "schema_version": 1,
        "observed_at": observed_at,
        "occupied_versions": {
            "windows_installer": ["3.2.205", "3.2.158+setup.1"],
            "windows_agent": ["3.2.205"],
            "windows_full_setup": ["3.2.264"],
            "linux_native": ["3.2.183"],
            "core": [
                {"version": "3.2.60000", "platform": "windows_amd64", "channel": "canary"},
                {"version": "3.2.277", "platform": "linux_amd64", "channel": "canary"},
            ],
        },
    }
    write(tmp_path / "production.json", snapshot)
    snapshot["occupied_versions"]["windows_full_setup"].append("3.2.275")
    write(tmp_path / "staging.json", snapshot)
    write(tmp_path / "candidates.json", {
        "schema_version": 1, "observed_at": observed_at,
        "windows": ["3.2.276"], "alt": ["3.2.274"],
    })
    return repo, tmp_path


def reserve(inputs, request_id, platform="windows", *options):
    repo, folder = inputs
    return subprocess.run(
        [
            sys.executable, str(CLI), "reserve", "--repo-root", str(repo),
            "--platform", platform, "--after", "3.2.205", "--request-id", str(request_id),
            "--production-snapshot", str(folder / "production.json"),
            "--staging-snapshot", str(folder / "staging.json"),
            "--candidate-inventory", str(folder / "candidates.json"),
            *options,
        ],
        capture_output=True, text=True, encoding="utf-8", timeout=90,
    )


def value(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_preview_respects_both_providers_and_local_candidates_without_pushing(release_inputs):
    repo, _ = release_inputs
    revision = git(repo, "rev-parse", "HEAD")
    result = value(reserve(release_inputs, uuid4(), "windows", "--dry-run"))
    assert result["state"] == "proposed"
    assert result["version"] == "3.2.278"
    assert result["source_revision"] == revision
    assert git(repo, "ls-remote", "origin", LEDGER) == ""


def test_parallel_windows_and_alt_reservations_are_unique_and_replay_safe(release_inputs):
    repo, _ = release_inputs
    requests = ((uuid4(), "windows"), (uuid4(), "alt"))
    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [executor.submit(reserve, release_inputs, *request) for request in requests]
        records = [value(result.result()) for result in pending]

    assert {entry["version"] for entry in records} == {"3.2.278", "3.2.279"}
    assert all(entry["state"] == "reserved" for entry in records)
    before = git(repo, "ls-remote", "origin", LEDGER)
    assert value(reserve(release_inputs, *requests[0])) == records[0]
    conflict = reserve(release_inputs, requests[0][0], "alt")
    assert conflict.returncode != 0
    assert "already bound" in conflict.stderr
    assert git(repo, "ls-remote", "origin", LEDGER) == before


@pytest.mark.parametrize("defect", ["missing", "stale", "incomplete", "same_snapshot"])
def test_reservation_requires_complete_recent_provider_views(release_inputs, defect):
    repo, folder = release_inputs
    staging = folder / "staging.json"
    if defect == "missing":
        staging.unlink()
    else:
        data = json.loads(staging.read_text(encoding="utf-8"))
        if defect == "stale":
            data["observed_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        elif defect == "incomplete":
            del data["occupied_versions"]["linux_native"]
        else:
            data = json.loads((folder / "production.json").read_text(encoding="utf-8"))
        write(staging, data)

    result = reserve(release_inputs, uuid4())
    assert result.returncode != 0
    assert result.stdout == ""
    assert git(repo, "ls-remote", "origin", LEDGER) == ""


def test_preview_sees_release_receipts_on_unfetched_remote_branch(release_inputs):
    repo, folder = release_inputs
    publisher = folder / "publisher"
    git(folder, "clone", "-b", "main", str(folder / "shared.git"), str(publisher))
    git(publisher, "config", "user.name", "Release Publisher")
    git(publisher, "config", "user.email", "release@example.invalid")
    git(publisher, "switch", "-c", "codex/remote-alt-candidate")
    write(publisher / "docs/releases/alt-3.2.281-candidate.json", {"version": "3.2.281"})
    git(publisher, "add", ".")
    git(publisher, "commit", "-m", "test: introduce remote release evidence")
    git(publisher, "push", "origin", "HEAD")
    before = git(repo, "for-each-ref", "--format=%(refname) %(objectname)")
    result = value(reserve(release_inputs, uuid4(), "alt", "--dry-run"))
    assert result["version"] == "3.2.282"
    assert git(repo, "for-each-ref", "--format=%(refname) %(objectname)") == before


def test_parallel_retries_with_one_request_write_one_reservation(release_inputs):
    request = uuid4()
    with ThreadPoolExecutor(max_workers=2) as executor:
        commands = [executor.submit(reserve, release_inputs, request, "both") for _ in range(2)]
        records = [value(command.result()) for command in commands]

    repo, _ = release_inputs
    assert records[0] == records[1]
    ledger = json.loads(git(repo, "--git-dir", str(repo.parent / "shared.git"), "show",
                            f"{LEDGER}:reservations.json"))
    assert ledger["reservations"] == records[:1]


def bind_source(repo, request_id):
    return subprocess.run(
        [sys.executable, str(CLI), "bind-source", "--repo-root", str(repo),
         "--request-id", str(request_id)],
        capture_output=True, text=True, encoding="utf-8", timeout=90,
    )


def test_bind_source_requires_reserved_version_and_cannot_rebind(release_inputs):
    repo, _ = release_inputs
    request = uuid4()
    reservation = value(reserve(release_inputs, request, "both"))

    wrong = bind_source(repo, request)
    assert wrong.returncode != 0
    assert "AGENT_VERSION" in wrong.stderr

    (repo / "pc_agent/version.py").write_text(
        f'AGENT_VERSION = "{reservation["version"]}"\n', encoding="utf-8",
    )
    dirty = bind_source(repo, request)
    assert dirty.returncode != 0
    assert "clean checkout" in dirty.stderr
    git(repo, "add", "pc_agent/version.py")
    git(repo, "commit", "-m", "test: pin the candidate build source")
    revision = git(repo, "rev-parse", "HEAD")
    bound = value(bind_source(repo, request))
    assert bound["source_revision"] == reservation["source_revision"]
    assert bound["build_revision"] == revision
    assert bound["version"] == reservation["version"]
    before = git(repo, "ls-remote", "origin", LEDGER)
    assert value(bind_source(repo, request)) == bound

    git(repo, "commit", "--allow-empty", "-m", "test: simulate a different candidate source")
    rejected = bind_source(repo, request)
    assert rejected.returncode != 0
    assert "already bound" in rejected.stderr
    assert git(repo, "ls-remote", "origin", LEDGER) == before
