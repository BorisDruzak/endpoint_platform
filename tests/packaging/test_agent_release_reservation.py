"""Exercise reservation through the CLI and a real shared Git remote."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
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
