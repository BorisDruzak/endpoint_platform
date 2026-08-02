from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


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


def _manifest(root: Path, *, version: str, guid: str, name: str | None = None) -> Path:
    source = root / "runtime.py"
    source.write_text("runtime-source", encoding="utf-8")
    path = root / (name or f"{version}.json")
    path.write_text(json.dumps({
        "schema_version": 1,
        "version": version,
        "component_guid": guid,
        "source_files": [{
            "path": "runtime.py",
            "sha256": hashlib.sha256(b"runtime-source").hexdigest(),
        }],
    }), encoding="utf-8")
    return path


def test_routine_build_accepts_only_the_checked_in_identity(tmp_path: Path) -> None:
    """A repeat build must bind the exact reviewed version, GUID, and source bytes."""
    validate_initial_runtime = _contract_module().validate_initial_runtime

    baseline = _manifest(
        tmp_path, version="3.1.76", guid="980AE24B-57BC-4B59-A18A-65B9B33A7906"
    )

    identity = validate_initial_runtime(tmp_path, baseline, baseline)

    assert identity.version == "3.1.76"
    assert identity.component_guid == "980AE24B-57BC-4B59-A18A-65B9B33A7906"
    (tmp_path / "runtime.py").write_text("rebuilt-behind-same-label", encoding="utf-8")
    with pytest.raises(ValueError, match="source hash"):
        validate_initial_runtime(tmp_path, baseline, baseline)


def test_transition_requires_two_approvals_and_new_component_identity(tmp_path: Path) -> None:
    """Approved bytes cannot reuse the old absolute path/component identity."""
    validate_initial_runtime = _contract_module().validate_initial_runtime

    baseline = _manifest(
        tmp_path, version="3.1.76", guid="980AE24B-57BC-4B59-A18A-65B9B33A7906"
    )
    transition = _manifest(
        tmp_path, version="3.1.77", guid="D53E70D8-CAD1-4755-9AC8-36164A48C9D5"
    )

    with pytest.raises(ValueError, match="two explicit approvals"):
        validate_initial_runtime(tmp_path, transition, baseline, approve_version=True)

    identity = validate_initial_runtime(
        tmp_path,
        transition,
        baseline,
        approve_version=True,
        approve_source=True,
    )
    assert identity.version == "3.1.77"
    assert identity.component_guid == "D53E70D8-CAD1-4755-9AC8-36164A48C9D5"

    same_identity = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        name="same-identity-transition.json",
    )
    with pytest.raises(ValueError, match="new version and component GUID"):
        validate_initial_runtime(
            tmp_path,
            same_identity,
            baseline,
            approve_version=True,
            approve_source=True,
        )


def test_approved_transition_validates_new_bytes_not_unavailable_old_bytes(
    tmp_path: Path,
) -> None:
    """A real source transition necessarily makes the old source hash unavailable."""
    validate_initial_runtime = _contract_module().validate_initial_runtime
    baseline = _manifest(
        tmp_path,
        version="3.1.76",
        guid="980AE24B-57BC-4B59-A18A-65B9B33A7906",
        name="baseline.json",
    )
    (tmp_path / "runtime.py").write_text("new-runtime-source", encoding="utf-8")
    transition = tmp_path / "transition.json"
    transition.write_text(json.dumps({
        "schema_version": 1,
        "version": "3.1.77",
        "component_guid": "D53E70D8-CAD1-4755-9AC8-36164A48C9D5",
        "source_files": [{
            "path": "runtime.py",
            "sha256": hashlib.sha256(b"new-runtime-source").hexdigest(),
        }],
    }), encoding="utf-8")

    identity = validate_initial_runtime(
        tmp_path,
        transition,
        baseline,
        approve_version=True,
        approve_source=True,
    )

    assert identity.version == "3.1.77"
