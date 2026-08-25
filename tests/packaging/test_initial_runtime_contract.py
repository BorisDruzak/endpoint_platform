from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


TOOLCHAIN_A = {
    "implementation": "CPython",
    "platform": "win-amd64",
    "pyinstaller_version": "6.19.0",
    "python_version": "3.14.3",
    "source_date_epoch": 1767225600,
}
TOOLCHAIN_B = {**TOOLCHAIN_A, "pyinstaller_version": "6.20.0"}
TOOLCHAIN_DETERMINISTIC = {**TOOLCHAIN_A, "python_hash_seed": "0"}
TOOLCHAIN_HOOKS_PINNED = {
    **TOOLCHAIN_DETERMINISTIC,
    "pyinstaller_hooks_contrib_version": "2026.2",
}


def _contract_module():
    import importlib.util
    import sys

    path = Path(__file__).resolve().parents[2] / "packaging" / "windows" / "initial_runtime_contract.py"
    spec = importlib.util.spec_from_file_location("initial_runtime_contract", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _artifact_identity(root: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    for path in files:
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        digest.update(
            f"{relative}\0{len(content)}\0{hashlib.sha256(content).hexdigest()}\n".encode()
        )
    return {"file_count": len(files), "tree_sha256": digest.hexdigest()}


def _source_hash(content: bytes) -> str:
    return hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()


def _manifest(
    root: Path,
    *,
    version: str,
    guid: str,
    artifact_root: Path,
    name: str | None = None,
    source_content: str = "runtime-source",
    toolchain: dict[str, object] = TOOLCHAIN_A,
    schema_version: int = 2,
) -> Path:
    source = root / "runtime.py"
    source.write_text(source_content, encoding="utf-8")
    version_file = root / "pc_agent" / "version.py"
    version_file.parent.mkdir(exist_ok=True)
    version_file.write_text(f'AGENT_VERSION = "{version}"\n', encoding="utf-8")
    path = root / (name or f"{version}.json")
    path.write_text(json.dumps({
        "agent_version": version,
        "artifact": _artifact_identity(artifact_root),
        "component_guid": guid,
        "schema_version": schema_version,
        "source_files": [
            {
                "path": "pc_agent/version.py",
                "sha256": _source_hash(version_file.read_bytes()),
            },
            {
                "path": "runtime.py",
                "sha256": _source_hash(source_content.encode()),
            },
        ],
        "toolchain": toolchain,
        "version": version,
    }), encoding="utf-8")
    return path


@pytest.fixture
def artifact_root(tmp_path: Path) -> Path:
    root = tmp_path / "artifact"
    (root / "_internal").mkdir(parents=True)
    (root / "pc_agent.exe").write_bytes(b"exe-v1")
    (root / "_internal" / "python314.dll").write_bytes(b"python-runtime")
    return root


def test_routine_build_accepts_only_the_checked_in_identity(
    tmp_path: Path, artifact_root: Path
) -> None:
    """A repeat build must bind the exact reviewed version, GUID, and source bytes."""
    validate = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
    )

    identity = validate(
        tmp_path,
        baseline,
        baseline,
        artifact_root=artifact_root,
        observed_toolchain=TOOLCHAIN_A,
    )

    assert identity.version == "3.1.76"
    assert identity.component_guid == "980AE24B-57BC-4B59-A18A-65B9B33A7906"
    (tmp_path / "runtime.py").write_text("rebuilt-behind-same-label", encoding="utf-8")
    with pytest.raises(ValueError, match="source hash"):
        validate(tmp_path, baseline, baseline, observed_toolchain=TOOLCHAIN_A)


def test_source_hash_validation_canonicalizes_python_line_endings(
    tmp_path: Path, artifact_root: Path
) -> None:
    """A Windows checkout must validate the same reviewed Python source bytes."""
    validate = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
        source_content="runtime-source\n",
    )
    (tmp_path / "runtime.py").write_bytes(b"runtime-source\r\n")

    identity = validate(
        tmp_path,
        baseline,
        baseline,
        observed_toolchain=TOOLCHAIN_A,
    )

    assert identity.version == "3.1.76"


def test_manifest_version_must_match_agent_version_constant(
    tmp_path: Path, artifact_root: Path
) -> None:
    """A directory label cannot claim a version different from the frozen runtime."""
    validate = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
    )
    (tmp_path / "pc_agent" / "version.py").write_text(
        'AGENT_VERSION = "3.1.75"\n', encoding="utf-8"
    )

    with pytest.raises(ValueError, match="AGENT_VERSION"):
        validate(tmp_path, baseline, baseline, observed_toolchain=TOOLCHAIN_A)


def test_routine_build_rejects_changed_complete_staged_payload(
    tmp_path: Path, artifact_root: Path
) -> None:
    """Matching source cannot bless a different DLL or PyInstaller bootloader."""
    validate = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
    )
    (artifact_root / "_internal" / "python314.dll").write_bytes(b"different-runtime")

    with pytest.raises(ValueError, match="staged payload"):
        validate(
            tmp_path,
            baseline,
            baseline,
            artifact_root=artifact_root,
            observed_toolchain=TOOLCHAIN_A,
        )


def test_transition_requires_two_approvals_and_new_component_identity(
    tmp_path: Path, artifact_root: Path
) -> None:
    """Approved bytes cannot reuse the old absolute path/component identity."""
    validate = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
        name="baseline.json",
    )
    transition = _manifest(
        tmp_path,
        version="3.1.77",
        guid="D53E70D8-CAD1-4755-9AC8-36164A48C9D5",
        artifact_root=artifact_root,
        name="transition.json",
        source_content="new-runtime-source",
    )

    with pytest.raises(ValueError, match="two explicit approvals"):
        validate(
            tmp_path,
            transition,
            baseline,
            approve_version=True,
            observed_toolchain=TOOLCHAIN_A,
        )

    identity = validate(
        tmp_path,
        transition,
        baseline,
        approve_version=True,
        approve_source=True,
        artifact_root=artifact_root,
        observed_toolchain=TOOLCHAIN_A,
    )
    assert identity.version == "3.1.77"

    same_identity = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
        name="same-identity-transition.json",
    )
    with pytest.raises(ValueError, match="new version and component GUID"):
        validate(
            tmp_path,
            same_identity,
            baseline,
            approve_version=True,
            approve_source=True,
            observed_toolchain=TOOLCHAIN_A,
        )


def test_toolchain_change_requires_a_dual_approved_transition(
    tmp_path: Path, artifact_root: Path
) -> None:
    """A different PyInstaller producer cannot silently rebuild the pinned label."""
    validate = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
        name="baseline.json",
    )

    with pytest.raises(ValueError, match="toolchain"):
        validate(tmp_path, baseline, baseline, observed_toolchain=TOOLCHAIN_B)

    transition = _manifest(
        tmp_path,
        version="3.1.77",
        guid="D53E70D8-CAD1-4755-9AC8-36164A48C9D5",
        artifact_root=artifact_root,
        name="transition.json",
        source_content="new-runtime-source",
        toolchain=TOOLCHAIN_B,
    )
    identity = validate(
        tmp_path,
        transition,
        baseline,
        approve_version=True,
        approve_source=True,
        artifact_root=artifact_root,
        observed_toolchain=TOOLCHAIN_B,
    )

    assert identity.version == "3.1.77"


def test_schema3_runtime_transition_requires_the_pinned_python_hash_seed(
    tmp_path: Path, artifact_root: Path
) -> None:
    """Archive entry order is part of the approved frozen runtime identity."""
    validate = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
        name="baseline.json",
    )
    transition = _manifest(
        tmp_path,
        version="3.1.77",
        guid="D53E70D8-CAD1-4755-9AC8-36164A48C9D5",
        artifact_root=artifact_root,
        name="transition.json",
        source_content="new-runtime-source",
        toolchain=TOOLCHAIN_DETERMINISTIC,
        schema_version=3,
    )

    with pytest.raises(ValueError, match="toolchain"):
        validate(
            tmp_path,
            transition,
            baseline,
            approve_version=True,
            approve_source=True,
            observed_toolchain={**TOOLCHAIN_A, "python_hash_seed": "random"},
        )

    identity = validate(
        tmp_path,
        transition,
        baseline,
        approve_version=True,
        approve_source=True,
        observed_toolchain=TOOLCHAIN_DETERMINISTIC,
    )

    assert identity.version == "3.1.77"


def test_schema4_runtime_transition_requires_the_pinned_contrib_hooks(
    tmp_path: Path, artifact_root: Path
) -> None:
    """Frozen bytes must not silently change with the PyInstaller hook bundle."""
    validate = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        artifact_root=artifact_root,
        name="baseline.json",
    )
    transition = _manifest(
        tmp_path,
        version="3.1.77",
        guid="D53E70D8-CAD1-4755-9AC8-36164A48C9D5",
        artifact_root=artifact_root,
        name="transition.json",
        source_content="new-runtime-source",
        toolchain=TOOLCHAIN_HOOKS_PINNED,
        schema_version=4,
    )

    with pytest.raises(ValueError, match="toolchain"):
        validate(
            tmp_path,
            transition,
            baseline,
            approve_version=True,
            approve_source=True,
            observed_toolchain={
                **TOOLCHAIN_HOOKS_PINNED,
                "pyinstaller_hooks_contrib_version": "2026.1",
            },
        )

    identity = validate(
        tmp_path,
        transition,
        baseline,
        approve_version=True,
        approve_source=True,
        artifact_root=artifact_root,
        observed_toolchain=TOOLCHAIN_HOOKS_PINNED,
    )

    assert identity.version == "3.1.77"


def test_windows_current_product_uses_a_checked_in_approved_initial_transition() -> None:
    """A source-version change must also advance the MSI-owned immutable runtime."""
    project_root = Path(__file__).resolve().parents[2]
    baseline = project_root / "packaging" / "windows" / "initial-runtime.json"
    transition = project_root / "packaging" / "windows" / "initial-runtime-3.2.27.json"

    assert transition.is_file()
    payload = json.loads(transition.read_text(encoding="utf-8"))
    assert payload["version"] == "3.2.27"
    assert payload["component_guid"] != json.loads(baseline.read_text(encoding="utf-8"))["component_guid"]
    assert "pc_agent/platform/windows/service_control.py" in {
        item["path"] for item in payload["source_files"]
    }
    assert "pc_agent/platform/windows/provision.py" in {
        item["path"] for item in payload["source_files"]
    }
    assert "pc_agent/platform/windows/acl.py" in {
        item["path"] for item in payload["source_files"]
    }
    assert "pc_agent/runtime/application.py" in {
        item["path"] for item in payload["source_files"]
    }
    assert "pc_agent/platform/windows/online_update_runtime.py" in {
        item["path"] for item in payload["source_files"]
    }
    assert "pc_agent/platform/windows/updater_service.py" in {
        item["path"] for item in payload["source_files"]
    }
    assert "pc_agent/platform/windows/canary_status.py" in {
        item["path"] for item in payload["source_files"]
    }

    validate = _contract_module().validate_initial_runtime
    identity = validate(
        project_root,
        transition,
        baseline,
        approve_version=True,
        approve_source=True,
        observed_toolchain=payload["toolchain"],
    )

    assert identity.transition_approved is True
