from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools/release/agent_release.py"
CATALOG = Path("docs/releases/current-agent-release.json")


def release_status(root, *options):
    return subprocess.run(
        [sys.executable, str(CLI), "status", "--repo-root", str(root), *options],
        capture_output=True, text=True, encoding="utf-8", check=False,
    )


def copy_release_records(tmp_path):
    shutil.copytree(ROOT / "docs/releases", tmp_path / "docs/releases")
    return tmp_path / CATALOG


def test_status_projects_current_pointers_without_confusing_channels():
    result = release_status(ROOT)
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["freshness"] == "repository_record"
    records = json.loads((ROOT / CATALOG).read_text(encoding="utf-8"))
    assert status["historical_checkpoint_version"] == records["version"]

    windows = status["windows"]
    assert windows["primary"]["version"] == records["primary_windows_release"]["version"]
    assert windows["primary"]["release_id"] != windows["existing_device_delivery"]["release_id"]
    assert windows["existing_device_delivery"]["enabled"] is records["current_windows_rollout"]["policy"]["enabled"]
    assert windows["enrollment"]["state"] == "unknown"

    assert status["alt"]["primary"]["version"] == records["linux"]["version"]
    assert status["alt"]["enrollment"]["release_id"]
    assert status["alt"]["enrollment"]["state"] == "catalog_recorded"
    assert status["ubuntu"]["apt"]["version"] == records["ubuntu_servers_197"]["version"]
    assert status["debian"]["apt"]["version"] == records["proxmox_debian"]["version"]
    assert status["provider"]["source_revision"]


def test_status_does_not_copy_primary_digest_to_a_different_rollout(tmp_path):
    catalog = copy_release_records(tmp_path)
    records = json.loads(catalog.read_text(encoding="utf-8"))
    delivery = records["current_windows_rollout"]
    delivery["release"] = "3.2.264"
    delivery["policy"]["release_id"] = "a9789ad6-353d-4d1f-a11e-9f7292736d62"
    catalog.write_text(json.dumps(records), encoding="utf-8")

    result = release_status(tmp_path)

    assert result.returncode == 0, result.stderr
    windows = json.loads(result.stdout)["windows"]
    assert windows["primary"]["version"] == records["primary_windows_release"]["version"]
    assert windows["existing_device_delivery"]["version"] == "3.2.264"
    assert windows["existing_device_delivery"]["sha256"] is None


def test_status_rejects_an_inconsistent_primary_receipt(tmp_path):
    catalog = copy_release_records(tmp_path)
    records = json.loads(catalog.read_text(encoding="utf-8"))
    records["primary_windows_release"]["version"] = "0.0.0"
    catalog.write_text(json.dumps(records), encoding="utf-8")

    result = release_status(tmp_path)

    assert result.returncode != 0
    assert "Windows primary release version differs from its receipt" in result.stderr
    assert result.stdout == ""


def test_status_rejects_primary_receipt_outside_release_directory(tmp_path):
    catalog = copy_release_records(tmp_path)
    records = json.loads(catalog.read_text(encoding="utf-8"))
    records["primary_windows_release"]["record"] = "docs/releases/../escape.json"
    catalog.write_text(json.dumps(records), encoding="utf-8")

    result = release_status(tmp_path)

    assert result.returncode != 0
    assert "Expected a separate JSON receipt under docs/releases" in result.stderr
    assert result.stdout == ""


def test_status_combines_current_provider_facts_with_repository_pointers(tmp_path):
    observed = datetime.now(timezone.utc).isoformat()
    active_source = {"platform": "alt", "version": "3.2.183", "catalog_campaign_count": 1}
    candidate_source = {
        "platform": "alt", "version": "3.2.277", "release_id": "candidate",
        "package_sha256": "d" * 64, "sensor_sha256": "e" * 64,
        "catalog_campaign_count": 0, "download_published": None, "retired_at": None,
    }
    retired_source = {
        "platform": "windows", "version": "3.2.203", "release_id": "retired",
        "catalog_campaign_count": 0, "download_published": False, "retired_at": observed,
    }
    snapshot = {
        "schema_version": 1, "observed_at": observed, "database_name": "endpoint_platform",
        "database_revision": "0056_context_collection_history",
        "windows_primary": {"id": "download", "agent_version": "3.2.205", "sha256": "a" * 64},
        "windows_delivery": {"release_id": "delivery", "version": "3.2.264", "enabled": False},
        "windows_active_assignments": {"recovery_required": 1, "verified": 2},
        "accepted_native_installations": [{"version": "3.2.183", "accepted_devices": 10, "connected_devices": 9}],
        "release_planning": {
            "enrollment_sources": [active_source, candidate_source, retired_source],
            "pending_enrollments": [],
            "windows_qualifications": [{"qualification_id": "qualification", "sha256": "b" * 64}],
        },
    }
    path = tmp_path / "production.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    result = release_status(ROOT, "--production-snapshot", str(path))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["freshness"] == "repository_record"
    production = report["provider_observations"]["production"]
    assert production["windows_download"]["id"] == "download"
    assert production["windows_full_setup_policy"]["release_id"] == "delivery"
    assert production["windows_active_assignments"]["recovery_required"] == 1
    assert production["accepted_native_installations"][0]["accepted_devices"] == 10
    assert production["registered_installer_sources"] == [active_source, candidate_source, retired_source]
    assert production["active_enrollment_sources"] == [active_source]
    assert production["windows_active_qualifications"][0]["qualification_id"] == "qualification"
