"""Exercise reservation through the CLI and a real shared Git remote."""
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from uuid import uuid4
from zipfile import ZipFile

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


def record_candidate(repo, request, platform, manifest, *options):
    return subprocess.run(
        [sys.executable, str(CLI), "record-candidate", "--repo-root", str(repo),
         "--request-id", str(request), "--platform", platform, "--manifest", str(manifest), *options],
        capture_output=True, text=True, encoding="utf-8", timeout=90,
    )


def prepare_bound_source(inputs):
    repo, _ = inputs
    request = uuid4()
    reservation = value(reserve(inputs, request, "both"))
    (repo / "pc_agent/version.py").write_text(
        f'AGENT_VERSION = "{reservation["version"]}"\n', encoding="utf-8",
    )
    git(repo, "add", "pc_agent/version.py")
    git(repo, "commit", "-m", "test: prepare candidate source")
    return request, value(bind_source(repo, request))


def test_qualify_build_plans_the_canonical_native_builder_without_writing(release_inputs):
    repo, folder = release_inputs
    baseline = git(repo, "rev-parse", "HEAD")
    recipe = repo / "packaging/alt/build-rpm.sh"
    recipe.parent.mkdir(parents=True)
    recipe.write_text("exit 99\n", encoding="utf-8")
    git(repo, "add", "packaging/alt/build-rpm.sh")
    git(repo, "commit", "-m", "test: change ALT native recipe")
    request, bound = prepare_bound_source(release_inputs)
    output = folder / "new-build"
    ledger = git(repo, "ls-remote", "origin", LEDGER)
    command = [sys.executable, str(CLI), "qualify-build", "--repo-root", str(repo),
               "--request-id", str(request), "--platform", "alt", "--base", baseline,
               "--output-root", str(output)]

    preview = value(subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=90))
    assert preview["state"] == "preview"
    assert preview["artifact"] == "alt_native_rpm"
    assert preview["builder"] == "packaging/alt/build-rpm.sh"
    assert preview["build_revision"] == bound["build_revision"]
    assert preview["version"] == bound["version"]
    assert not output.exists()
    assert git(repo, "ls-remote", "origin", LEDGER) == ledger

    (repo / "unqueued.json").write_text("{}", encoding="utf-8")
    dirty = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert dirty.returncode != 0 and "clean checkout" in dirty.stderr
    assert not output.exists()
    (repo / "unqueued.json").unlink()
    git(repo, "commit", "--allow-empty", "-m", "test: leave the bound checkout")
    wrong_source = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert wrong_source.returncode != 0 and "bound build revision" in wrong_source.stderr
    assert not output.exists()


@pytest.mark.skipif(sys.platform != "win32" or not shutil.which("pwsh"), reason="Windows Core packaging needs PowerShell 7")
def test_qualify_build_invokes_windows_core_packager_and_freezes_output(release_inputs):
    repo, folder = release_inputs
    baseline = git(repo, "rev-parse", "HEAD")
    relative = "packaging/windows/build-update-zip.ps1"
    script = repo / relative
    script.parent.mkdir(parents=True)
    shutil.copyfile(CLI.parents[2] / relative, script)
    git(repo, "add", relative)
    git(repo, "commit", "-m", "test: change the Core ZIP recipe")
    request, bound = prepare_bound_source(release_inputs)
    version, revision = bound["version"], bound["build_revision"]
    runtime = folder / "frozen runtime"
    runtime.mkdir()
    contract = {"schema_version": 1, "version": version, "source_revision": revision,
                "minimum_launcher_version": "3.2.205"}
    (runtime / "endpoint-runtime-contract.json").write_text(
        json.dumps(contract, sort_keys=True, separators=(",", ":")), encoding="utf-8",
    )
    inputs = folder / "core-inputs.json"
    write(inputs, {"runtime_root": runtime.name})
    output = folder / "build result"
    command = [sys.executable, str(CLI), "qualify-build", "--repo-root", str(repo),
               "--request-id", str(request), "--platform", "windows", "--base", baseline,
               "--output-root", str(output), "--inputs", str(inputs), "--execute"]
    low = subprocess.run(command + ["--observed-launcher", "3.2.204"], capture_output=True,
                         text=True, encoding="utf-8", timeout=90)
    assert low.returncode != 0 and "below the candidate minimum" in low.stderr
    assert not output.exists()

    valid = command + ["--observed-launcher", "3.2.205"]
    failed_output = folder / "failed"
    failed = valid.copy()
    failed[failed.index(str(output))] = str(failed_output)
    error = subprocess.run(failed, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert error.returncode != 0 and "builder exited" in error.stderr
    assert "pc_agent.exe" in (failed_output / "builder.log").read_text(encoding="utf-8")
    assert not (failed_output / "qualification-build.json").exists()

    compile_script = folder / "compile.ps1"
    compile_script.write_text(
        'param([string]$Destination)\n$ErrorActionPreference = "Stop"\n'
        "Add-Type -OutputType ConsoleApplication -OutputAssembly $Destination -TypeDefinition @'\n"
        'public static class VersionProbe { public static void Main(string[] args) { '
        f'System.Console.WriteLine("{version}"); }} }}\n'
        "'@\n",
        encoding="utf-8",
    )
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(compile_script),
                    str(runtime / "pc_agent.exe")], check=True, capture_output=True, timeout=30)
    before = git(repo, "ls-remote", "origin", LEDGER)
    result = value(subprocess.run(valid, capture_output=True, text=True, encoding="utf-8", timeout=90))
    assert result["state"] == "built" and result["artifact"] == "windows_core_zip"
    record, = result["outputs"]
    archive = output / record["path"]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == record["sha256"]
    assert json.loads((output / "qualification-build.json").read_bytes()) == result
    with ZipFile(archive) as zip_file:
        assert json.loads(zip_file.read("endpoint-runtime-contract.json")) == contract
    assert git(repo, "ls-remote", "origin", LEDGER) == before
    assert subprocess.run(valid, capture_output=True, timeout=90).returncode != 0
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == record["sha256"]


def windows_candidate(folder, version, revision, setup_content=b"setup bytes"):
    setup = folder / f"EndpointAgentSetup-{version}-x64.exe"
    msi = folder / f"EndpointAgent-{version}-x64.msi"
    setup.write_bytes(setup_content)
    msi.write_bytes(b"msi bytes")
    setup_sha, msi_sha = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (setup, msi)]
    sidecar = setup.with_suffix(".release.json")
    write(sidecar, {
        "schema_version": "endpoint_windows_setup_release_v1", "version": version,
        "agent_version": version, "source_commit": revision, "msi_source_commit": revision,
        "filename": setup.name, "setup_sha256": setup_sha, "msi_sha256": msi_sha,
        "authenticode_status": "valid", "msi_authenticode_status": "valid",
        "authenticode_publisher": "CN=Endpoint Fixture", "msi_authenticode_publisher": "CN=Endpoint Fixture",
    })
    write(msi.with_suffix(".release.json"), {
        "schema_version": "endpoint_windows_release_v1", "version": version,
        "source_revision": revision, "package_sha256": msi_sha,
        "product_code": "{00000000-0000-0000-0000-000000000001}",
    })
    return setup, sidecar


def test_record_windows_candidate_is_idempotent_and_rejects_replacement(release_inputs):
    repo, folder = release_inputs
    request, bound = prepare_bound_source(release_inputs)
    setup, manifest = windows_candidate(folder, bound["version"], bound["build_revision"])
    publisher = ("--expected-publisher", "CN=Endpoint Fixture")
    candidate = value(record_candidate(repo, request, "windows", manifest, *publisher))
    assert candidate["state"] == "candidate"
    assert candidate["evidence"] == "artifact_fingerprints"
    assert candidate["build_revision"] == bound["build_revision"]
    assert candidate["artifacts"]["setup"]["sha256"] == hashlib.sha256(setup.read_bytes()).hexdigest()
    before = git(repo, "ls-remote", "origin", LEDGER)
    assert value(record_candidate(repo, request, "windows", manifest, *publisher)) == candidate
    setup.write_bytes(b"changed after validation")
    mismatch = record_candidate(repo, request, "windows", manifest, *publisher)
    assert mismatch.returncode != 0
    assert "digest" in mismatch.stderr
    windows_candidate(folder, bound["version"], bound["build_revision"], b"different consistent build")
    replacement = record_candidate(repo, request, "windows", manifest, *publisher)
    assert replacement.returncode != 0
    assert "already recorded" in replacement.stderr
    assert git(repo, "ls-remote", "origin", LEDGER) == before


def test_qualify_matrix_uses_the_candidate_bytes_and_rejects_changes(release_inputs):
    repo, folder = release_inputs
    request, bound = prepare_bound_source(release_inputs)
    setup, manifest = windows_candidate(folder, bound["version"], bound["build_revision"])
    candidate = value(record_candidate(repo, request, "windows", manifest,
                                       "--expected-publisher", "CN=Endpoint Fixture"))
    digest = candidate["artifacts"]["setup"]["sha256"]
    snapshot = folder / "snapshot.json"
    write(snapshot, {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
                     "release_planning": {"devices": [], "windows_targets": [],
                                          "pending_enrollments": [], "enrollment_sources": []}})
    prefix = [sys.executable, str(CLI)]
    binding = ["--repo-root", str(repo), "--request-id", str(request), "--platform", "windows"]
    matrix = prefix + ["qualify-matrix", *binding, "--snapshot", str(snapshot), "--artifacts-dir", str(folder)]
    before = git(repo, "ls-remote", "origin", LEDGER)
    report = value(subprocess.run(matrix, capture_output=True, text=True, encoding="utf-8", timeout=90))
    assert report["target"] == {"platform": "windows", "version": bound["version"], "sha256": digest}
    assert report["reservation"]["build_revision"] == bound["build_revision"]
    assert report["reservation"]["request_id"] == str(request)
    assert report["cases"][0]["test"] == "factory_first_registration"
    assert git(repo, "ls-remote", "origin", LEDGER) == before

    setup.write_bytes(b"different bytes")
    mismatch = subprocess.run(matrix, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert mismatch.returncode != 0 and "differs from the recorded candidate" in mismatch.stderr
    setup.write_bytes(b"setup bytes")
    value(subprocess.run(prefix + ["reject", *binding, "--sha256", digest, "--reason", "Lab rollback failed"],
                         capture_output=True, text=True, encoding="utf-8", timeout=90))
    refused = subprocess.run(matrix, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert refused.returncode != 0 and "Candidate is rejected" in refused.stderr


def test_promote_checks_the_recorded_bytes_before_opening_the_provider(release_inputs, monkeypatch):
    repo, folder = release_inputs
    request, bound = prepare_bound_source(release_inputs)
    setup, manifest = windows_candidate(folder, bound["version"], bound["build_revision"])
    msi_manifest = folder / f'EndpointAgent-{bound["version"]}-x64.release.json'
    write(manifest, {**json.loads(manifest.read_bytes()), "msi_source_commit": bound["source_revision"]})
    write(msi_manifest, {**json.loads(msi_manifest.read_bytes()), "source_revision": bound["source_revision"]})
    publisher = ["--expected-publisher", "CN=Endpoint Fixture"]
    value(record_candidate(repo, request, "windows", manifest, *publisher))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("ARTIFACT_ROOT", raising=False)
    command = [sys.executable, str(CLI), "promote", "--repo-root", str(repo), "--request-id", str(request),
               "--platform", "windows", "--artifacts-dir", str(folder), "--qualification-id", str(uuid4()), *publisher]
    before = git(repo, "ls-remote", "origin", LEDGER)
    missing = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert missing.returncode != 0 and "DATABASE_URL and ARTIFACT_ROOT" in missing.stderr
    setup.write_bytes(b"unrecorded bytes")
    changed = subprocess.run(command + ["--execute"], capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert changed.returncode != 0 and "differs from the recorded candidate" in changed.stderr
    assert git(repo, "ls-remote", "origin", LEDGER) == before


def test_record_windows_candidate_rejects_a_different_source_commit(release_inputs):
    repo, folder = release_inputs
    request, bound = prepare_bound_source(release_inputs)
    _, manifest = windows_candidate(folder, bound["version"], bound["source_revision"])
    before = git(repo, "ls-remote", "origin", LEDGER)
    rejected = record_candidate(repo, request, "windows", manifest,
                                "--expected-publisher", "CN=Endpoint Fixture")
    assert rejected.returncode != 0
    assert "differs from the bound build" in rejected.stderr
    assert git(repo, "ls-remote", "origin", LEDGER) == before


def test_reject_candidate_is_digest_bound_and_keeps_the_artifact_history(release_inputs):
    repo, folder = release_inputs
    request, bound = prepare_bound_source(release_inputs)
    _, manifest = windows_candidate(folder, bound["version"], bound["build_revision"])
    publisher = ("--expected-publisher", "CN=Endpoint Fixture")
    candidate = value(record_candidate(repo, request, "windows", manifest, *publisher))

    def run(command, *options):
        return subprocess.run(
            [sys.executable, str(CLI), command, "--repo-root", str(repo), "--request-id", str(request), *options],
            capture_output=True, text=True, encoding="utf-8", timeout=90,
        )

    def reject(digest, reason="Native recovery verification failed"):
        return run("reject", "--platform", "windows", "--sha256", digest, "--reason", reason)

    before = git(repo, "ls-remote", "origin", LEDGER)
    mismatch = reject("0" * 64)
    assert mismatch.returncode != 0
    assert "digest" in mismatch.stderr
    assert git(repo, "ls-remote", "origin", LEDGER) == before

    digest = candidate["artifacts"]["setup"]["sha256"]
    rejected = value(reject(digest))
    assert rejected["state"] == "rejected"
    assert rejected["artifacts"] == candidate["artifacts"]
    assert rejected["rejection"]["reason"] == "Native recovery verification failed"
    after = git(repo, "ls-remote", "origin", LEDGER)
    assert after != before
    assert value(reject(digest)) == rejected
    assert value(record_candidate(repo, request, "windows", manifest, *publisher)) == rejected
    assert value(run("status"))["candidates"] == {"windows": rejected}
    assert reject(digest, "Different reason").returncode != 0
    assert git(repo, "ls-remote", "origin", LEDGER) == after


def test_record_alt_candidate_verifies_archive_members_against_the_manifest(release_inputs):
    repo, folder = release_inputs
    request, bound = prepare_bound_source(release_inputs)
    version = bound["version"]
    name = f"endpoint-alt-pilot-{version}-1"
    public_key = CLI.parents[2] / "packaging/alt/pilot/endpoint-rpm-release.asc"
    files = {
        f"endpoint-agent-{version}-alt6.x86_64.rpm": b"core",
        f"endpoint-agent-user-sensor-{version}-alt6.x86_64.rpm": b"sensor",
        "endpoint-agent-setup": b"setup",
        public_key.name: public_key.read_bytes(),
    }
    manifest = folder / f"{name}.manifest.json"
    write(manifest, {
        "schema_version": "endpoint_alt_native_kit_v3", "kit_name": name,
        "agent_version": version, "agent_source_revision": bound["build_revision"],
        "frozen_manifest_sha256": "f"*64, "publisher_fingerprint": "BC24B8EE43DBB05A748E11A4343B5DA748370631",
        "files": {filename: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for filename, data in files.items()},
    })
    archive = folder / f"{name}.tar.gz"
    archive_signature = folder / f"{name}.tar.gz.sig"
    manifest_signature = folder / f"{manifest.name}.sig"
    archive_signature.write_bytes(b"detached archive signature fixture")
    manifest_signature.write_bytes(b"detached manifest signature fixture")
    options = ("--archive-signature", str(archive_signature), "--manifest-signature", str(manifest_signature))
    files["native-kit-manifest.json"] = manifest.read_bytes()

    def write_archive(payload):
        with tarfile.open(archive, "w:gz") as bundle:
            for filename, data in payload.items():
                member = tarfile.TarInfo(f"{name}/{filename}")
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))

    write_archive({**files, "endpoint-agent-setup": b"wrong"})
    rejected = record_candidate(repo, request, "alt", manifest, *options)
    assert rejected.returncode != 0
    assert "digest" in rejected.stderr
    write_archive(files)
    candidate = value(record_candidate(repo, request, "alt", manifest, *options))
    assert candidate["state"] == "candidate"
    assert candidate["artifacts"]["archive"]["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert candidate["artifacts"]["manifest_signature"]["sha256"] == hashlib.sha256(manifest_signature.read_bytes()).hexdigest()
    snapshot = folder / "lab-snapshot.json"
    write(snapshot, {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
                     "release_planning": {"devices": [], "windows_targets": [],
                                          "pending_enrollments": [], "enrollment_sources": []}})
    matrix = [sys.executable, str(CLI), "qualify-matrix", "--repo-root", str(repo), "--request-id", str(request),
              "--platform", "alt", "--snapshot", str(snapshot), "--artifacts-dir", str(folder)]
    report = value(subprocess.run(matrix, capture_output=True, text=True, encoding="utf-8", timeout=90))
    assert report["target"]["sha256"] == candidate["artifacts"]["archive"]["sha256"]
    archive_signature.write_bytes(b"different detached signature")
    mismatch = subprocess.run(matrix, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert mismatch.returncode != 0 and "differs from the recorded candidate" in mismatch.stderr
    native = [sys.executable, str(CLI), "register-alt-native", "--repo-root", str(repo),
              "--request-id", str(request), "--artifacts-dir", str(folder), "--reviewed-by", "Lab reviewer"]
    changed = subprocess.run(native, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert changed.returncode != 0 and "differs from the recorded candidate" in changed.stderr
    incoming = folder / "incoming"
    incoming.mkdir(mode=0o700)
    prepare = [sys.executable, str(CLI), "prepare-alt-download", "--repo-root", str(repo),
               "--request-id", str(request), "--artifacts-dir", str(folder),
               "--incoming-root", str(incoming), "--execute"]
    changed = subprocess.run(prepare, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert changed.returncode != 0 and "differs from the recorded candidate" in changed.stderr
    assert not list(incoming.iterdir())
    acceptance = [sys.executable, str(CLI), "qualify-alt-enrollment", "--repo-root", str(repo),
                  "--request-id", str(request), "--artifacts-dir", str(folder),
                  "--enrollment-request-id", str(uuid4()), "--device-id", str(uuid4())]
    changed = subprocess.run(acceptance, capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert changed.returncode != 0 and "differs from the recorded candidate" in changed.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Native download staging uses Linux owner permissions")
def test_alt_download_partial_copy_can_retry_and_cannot_overwrite_conflict(tmp_path, monkeypatch):
    from tools.release import agent_alt_download as download

    incoming = tmp_path / "incoming"
    incoming.mkdir(mode=0o700)
    destination = incoming / "endpoint-alt-pilot-3.2.274-1"
    name = f"{destination.name}.tar.gz"
    source = tmp_path / name
    source.write_bytes(b"verified archive")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    paths = {name: source}
    proofs = {name: {"filename": name, "size": source.stat().st_size, "sha256": digest}}

    def interrupted_copy(stream, output, length):
        output.write(stream.read(3))
        raise OSError(errno.ENOSPC, "full staging filesystem")

    assert download._prepare_directory(incoming, destination, paths, proofs, execute=False) == "preview"
    assert not list(incoming.iterdir())
    with monkeypatch.context() as patch:
        patch.setattr(download.shutil, "copyfileobj", interrupted_copy)
        with pytest.raises(OSError, match="full staging filesystem"):
            download._prepare_directory(incoming, destination, paths, proofs, execute=True)
    assert not list(incoming.iterdir())

    with ThreadPoolExecutor(max_workers=2) as workers:
        operations = [workers.submit(download._prepare_directory, incoming, destination, paths, proofs, execute=True)
                      for _ in range(2)]
        assert [operation.result() for operation in operations] == ["prepared", "prepared"]
    assert list(incoming.iterdir()) == [destination]
    assert (destination / name).read_bytes() == source.read_bytes()
    (destination / name).write_bytes(b"x" * source.stat().st_size)
    with pytest.raises(ValueError, match="conflicts"):
        download._prepare_directory(incoming, destination, paths, proofs, execute=True)
    assert (destination / name).read_bytes() == b"x" * source.stat().st_size


def test_alt_download_https_checks_response_bytes_and_never_follows_redirect(tmp_path, monkeypatch):
    from tools.release import agent_alt_download as download

    name = "endpoint-alt-pilot-3.2.274-1"
    payload = {f"{name}.tar.gz": b"archive", f"{name}.manifest.json": b"manifest"}
    payload.update({f"{filename}.sig": b"signature" for filename in list(payload)})
    key = (CLI.parents[2] / "packaging/alt/pilot/endpoint-rpm-release.asc").read_bytes()
    proofs = {filename: {"filename": filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
              for filename, data in payload.items()}
    candidate = {"request_id": str(uuid4()), "state": "candidate", "version": "3.2.274",
                 "artifacts": dict(zip(("archive", "manifest", "archive_signature", "manifest_signature"), proofs.values())),
                 "members": {"endpoint-rpm-release.asc": {"size": len(key), "sha256": hashlib.sha256(key).hexdigest()}}}
    for ext in (".tar.gz", ".manifest.json"):
        filename = name + ext
        payload[filename + ".sha256"] = f"{proofs[filename]['sha256']}  {filename}\n".encode("ascii")
    payload["endpoint-rpm-release.asc"] = key
    monkeypatch.setattr(download.agent_alt_native.agent_reservations, "reservation_status",
                        lambda args: {"candidates": {"alt": candidate}})
    calls = []
    response_status = {}

    class Response(io.BytesIO):
        def getheader(self, name):
            return str(len(payload[self.filename])) if name == "Content-Length" else None

    class Connection:
        def __init__(self, host, port, *, context, timeout):
            assert host == "stage.example.org" and port == 9443 and context is trusted_context

        def request(self, method, path, headers):
            assert path.startswith(f"/downloads/alt/{name}/")
            calls.append((method, path))

        def getresponse(self):
            method, path = calls[-1]
            filename = path.rsplit("/", 1)[-1]
            result = Response(payload[filename] if method == "GET" else b"")
            result.status = response_status.get(filename, 200)
            result.filename = filename
            return result

        def close(self):
            pass

    trusted_context = object()
    monkeypatch.setattr(download.ssl, "create_default_context", lambda *, cafile: trusted_context)
    monkeypatch.setattr(download, "HTTPSConnection", Connection)
    args = Namespace(origin="https://stage.example.org:9443", ca_file=tmp_path / "lab-ca.pem")
    assert len(download.verify_https(args)["files"]) == 7
    assert sorted(method for method, _ in calls) == ["GET"] * 7 + ["HEAD"] * 7

    payload[f"{name}.tar.gz"] = b"ARCHIVE"
    with pytest.raises(ValueError, match="digest"):
        download.verify_https(args)
    calls.clear()
    response_status[f"{name}.tar.gz"] = 302
    with pytest.raises(ValueError, match="302"):
        download.verify_https(args)
    assert calls == [("HEAD", f"/downloads/alt/{name}/{name}.tar.gz")]


def test_alt_qualification_stays_bound_to_the_candidate_and_expires(release_inputs):
    from tools.release import agent_alt_qualification as qualification, agent_reservations as ledger

    repo, _ = release_inputs
    request, reserved = prepare_bound_source(release_inputs)
    head = ledger._remote_head(repo)
    candidate = {key: reserved[key] for key in ("request_id", "version", "build_revision")}
    candidate.update(platform="alt", state="candidate", artifacts={"archive": {"sha256": "d"*64}})
    assert ledger._append(repo, head, ledger._with_candidate([reserved], reserved, candidate), "fixture alt candidate")
    now = datetime.now(timezone.utc)
    args = Namespace(repo_root=repo, request_id=request, qualification_id=uuid4(),
                     valid_until=(now + timedelta(hours=2)).isoformat())
    receipt = {key: candidate[key] for key in ("request_id", "version", "build_revision", "platform")}
    receipt.update(schema_version=1, state="accepted", scope="first_enrollment", kit_sha256="d"*64,
                   enrollment_status="device_registered", native_sequence=1, checked_at=now.isoformat(),
                   activity_collected_at=(now-timedelta(seconds=2)).isoformat())
    for name in ("device_id", "enrollment_request_id", "native_release_id", "native_event_id", "session_id", "baseline_snapshot_id"):
        receipt[name] = str(uuid4())
    before = ledger._remote_head(repo)
    with pytest.raises(ValueError, match="different candidate"):
        qualification.record(args, {**receipt, "kit_sha256":"c"*64}, now=now)
    assert ledger._remote_head(repo) == before
    stored = qualification.record(args, receipt, now=now)
    assert qualification.require(args, now=now)[1] == stored
    recorded_head = ledger._remote_head(repo)
    assert recorded_head != before
    assert qualification.record(args, receipt, now=now) == stored
    with pytest.raises(ValueError, match="already bound"):
        qualification.record(args, {**receipt, "native_event_id":str(uuid4())}, now=now)
    with pytest.raises(ValueError, match="expired"):
        qualification.require(args, now=now+timedelta(hours=2))
    assert ledger._remote_head(repo) == recorded_head
    ledger.reject_candidate(Namespace(repo_root=repo, request_id=request, platform="alt",
                                      sha256="d"*64, reason="Reviewed test rejection"))
    with pytest.raises(ValueError, match="rejected"):
        qualification.require(args, now=now)


@pytest.mark.skipif(sys.platform != "linux", reason="ALT static publication uses POSIX directory permissions")
def test_alt_publication_rolls_back_only_its_new_directory_and_retries_exact_bytes(tmp_path):
    from tools.release import agent_alt_publication as publication

    incoming = tmp_path / "incoming"
    incoming.mkdir(mode=0o700)
    distribution = tmp_path / "alt"
    distribution.mkdir(mode=0o755)
    folder = "endpoint-alt-pilot-3.2.274-1"
    target = distribution / folder
    paths = {"README.ru.md": b"fixture guide", folder+".tar.gz": b"verified archive"}
    proofs = {name: {"filename":name, "size":len(value), "sha256":hashlib.sha256(value).hexdigest()}
              for name,value in paths.items()}
    calls = []

    def validate():
        calls.append("eligibility")

    def check_worker(payload):
        assert (payload / "README.ru.md").stat().st_mode & 0o777 == 0o644
        assert not target.exists()
        calls.append("worker")

    def reject_served_bytes():
        assert (target / (folder+".tar.gz")).read_bytes() == b"verified archive"
        raise ValueError("served digest differs")

    with pytest.raises(ValueError, match="served digest differs"):
        publication._activate(incoming, target, paths, proofs, validate, check_worker, reject_served_bytes)
    assert not target.exists() and not list(incoming.iterdir())
    assert calls == ["worker", "eligibility"]

    def accept_served_bytes():
        assert all((target / name).read_bytes() == value for name,value in paths.items())
        calls.append("served")

    assert publication._activate(incoming, target, paths, proofs, validate, check_worker, accept_served_bytes)
    assert not publication._activate(incoming, target, paths, proofs, validate, check_worker, accept_served_bytes)
    with pytest.raises(ValueError, match="served digest differs"):
        publication._activate(incoming, target, paths, proofs, validate, check_worker, reject_served_bytes)
    assert (target / (folder+".tar.gz")).read_bytes() == b"verified archive"


def test_alt_publication_refuses_unreviewed_guide_bytes(tmp_path):
    from tools.release import agent_alt_publication as publication

    guide = tmp_path / "report.md"
    guide.write_bytes(b"reviewed public guide")
    digest = hashlib.sha256(guide.read_bytes()).hexdigest()
    assert publication._read_guide(guide, digest)[0] == b"reviewed public guide"
    guide.write_bytes(b"other guide")
    with pytest.raises(ValueError, match="guide digest"):
        publication._read_guide(guide, digest)
