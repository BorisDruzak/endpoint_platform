"""Cross-lineage wire compatibility only; no installed updater attestation."""
import ast
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


LEGACY_SOURCE = "c05bb0a528527ed1544c88fb0b1570c64b32084d"
ROOT = Path(__file__).resolve().parents[2]


def frozen_worker():
    result = subprocess.run(["git", "show", LEGACY_SOURCE + ":pc_agent/platform/windows/updater_service.py"],
        cwd=ROOT, capture_output=True, text=True, check=True, timeout=10)
    return ast.parse(result.stdout)


def test_current_pending_producer_matches_immutable81_validator_fields(tmp_path):
    import hashlib

    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.update_adapter import EndpointRecommendation

    legacy = frozen_worker()
    fields = next(node.value for node in legacy.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_PENDING_FIELDS" for target in node.targets))
    assert isinstance(fields, ast.Call) and isinstance(fields.func, ast.Name) and fields.func.id == "frozenset"
    expected = frozenset(ast.literal_eval(fields.args[0]))

    paths = WindowsUpdatePaths(tmp_path / "install", tmp_path / "updates/pending_update.json")
    paths.downloads_root.mkdir(parents=True)
    staged = paths.downloads_root / "download.zip.partial"
    artifact = paths.downloads_root / "build.zip"
    contents = b"fixture Core archive"
    staged.write_bytes(contents)
    recommendation = EndpointRecommendation(
        "caa31a48-bf2f-4c1c-8b77-d1be77e12b4e", "3.2.83", "windows_amd64", "canary",
        "https://endpoint.example.test/build.zip", artifact.name, "zip",
        hashlib.sha256(contents).hexdigest(), len(contents), "scheduled_rollout",
    )
    runtime = WindowsOnlineUpdateRuntime(
        adapter=None, paths=paths, acl=SimpleNamespace(protect_update_path=lambda _: None), download=None,
    )
    runtime._publish_download(recommendation, staged, artifact)

    pending = json.loads(paths.pending_path.read_bytes())
    assert pending.keys() == expected
    assert pending["artifact_path"] == str(artifact)
    assert artifact.read_bytes() == contents


@pytest.mark.parametrize("field,replacement", [(None, None), ("attempt_id", "other"),
    ("operation_id", "other"), ("version", "3.2.82"), ("status", "pending")])
def test_immutable81_reader_accepts_current_proof_only_for_its_attempt(tmp_path, monkeypatch, field, replacement):
    from pc_agent.platform.windows import startup_confirmation as current
    node = next(node for node in frozen_worker().body if isinstance(node, ast.ClassDef) and node.name == "FileStartupConfirmation")
    namespace = {"WindowsUpdatePaths": object, "datetime": datetime, "json": json,
        "_reject_reparse_path": lambda path: None}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "immutable81-FileStartupConfirmation", "exec"), namespace)
    paths = SimpleNamespace(updates_root=tmp_path, pending_path=tmp_path / "pending.json", current_path=tmp_path / "current.json")
    # Test-only producer/consumer records. No installed state is read or changed.
    paths.pending_path.write_text(json.dumps({"version": "3.2.83", "operation_id": "rollout-42"}), encoding="utf-8")
    paths.current_path.write_text(json.dumps({"schema_version": 1, "source_revision": "a" * 40, "version": "3.2.83"}), encoding="utf-8")
    (tmp_path / "startup-attempt.json").write_text(json.dumps({"version": "3.2.83", "operation_id": "rollout-42", "attempt_id": "attempt-7"}), encoding="utf-8")
    def write(path, payload, **kwargs):
        if field:
            payload[field] = replacement
        path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(current, "AGENT_VERSION", "3.2.83")
    # This checks cross-version JSON consumption, not OS ACL/durability behavior.
    monkeypatch.setattr(current, "_read_state", lambda path, limit: json.loads(path.read_text(encoding="utf-8")))
    monkeypatch.setattr(current, "write_json_atomic", write)
    assert current.StartupProofWriter(paths).record_after_server_handshake()
    assert namespace["FileStartupConfirmation"](paths).is_confirmed(version="3.2.83",
        operation_id="rollout-42", attempt_id="attempt-7", not_before=datetime.now(UTC) - timedelta(seconds=10)) is (field is None)
