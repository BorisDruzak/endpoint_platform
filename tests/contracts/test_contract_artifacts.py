import json
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from tools.contracts.generate_contract_artifacts import PUBLIC_MODELS, render_artifacts


SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:token|secret|password|credential|authorization|api[_-]?key)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?:\bbearer\s+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
    r"(?:sk|pk|api|tok|secret)_[A-Za-z0-9_-]{8,})",
    re.IGNORECASE,
)
ABSOLUTE_PATH_PATTERN = re.compile(r"^(?:[A-Za-z]:[\\/]|/|\\\\)")
OPAQUE_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,}$")
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
SYNTHETIC_UUIDS = {
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
}
DEVICE_DATA_MARKERS = ("device", "hardware", "host", "machine")


def _walk_json(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, key)
            yield child_path, child
            yield from _walk_json(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = (*path, str(index))
            yield child_path, child
            yield from _walk_json(child, child_path)


def _assert_synthetic_fixture(value: Any) -> None:
    for path, child in _walk_json(value):
        field_name = path[-1]
        assert not SENSITIVE_KEY_PATTERN.search(field_name), path
        if not isinstance(child, str):
            continue
        assert not SENSITIVE_VALUE_PATTERN.search(child), path
        assert not ABSOLUTE_PATH_PATTERN.search(child), path
        if UUID_PATTERN.fullmatch(child):
            assert child in SYNTHETIC_UUIDS, path
        elif field_name != "sha256":
            assert not OPAQUE_VALUE_PATTERN.fullmatch(child), path
        if any(marker in field_name.lower() for marker in DEVICE_DATA_MARKERS):
            assert child in SYNTHETIC_UUIDS or "fixture" in child.lower(), path


def _walk_local_refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str) and child.startswith("#"):
                yield child
            yield from _walk_local_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_local_refs(child)


def _resolve_json_pointer(document: dict[str, Any], reference: str) -> object:
    value: object = document
    for token in reference.removeprefix("#/").split("/"):
        assert isinstance(value, dict), reference
        value = value[token.replace("~1", "/").replace("~0", "~")]
    return value


@pytest.mark.parametrize("filename", PUBLIC_MODELS)
def test_fixture_validates_against_model_and_schema(filename: str) -> None:
    fixture = json.loads(
        (Path("tests/fixtures/contracts") / filename).read_text(encoding="utf-8")
    )
    schema = json.loads(
        (Path("contracts/jsonschema") / filename).read_text(encoding="utf-8")
    )

    PUBLIC_MODELS[filename].model_validate(fixture)
    Draft202012Validator(schema).validate(fixture)


def test_committed_contract_artifacts_match_renderer_without_mutation(tmp_path: Path) -> None:
    rendered = render_artifacts(tmp_path)

    assert not any(tmp_path.iterdir())
    assert rendered
    assert all(not relative_path.is_absolute() for relative_path in rendered)
    assert rendered == render_artifacts(tmp_path)
    for relative_path, expected in rendered.items():
        assert (Path.cwd() / relative_path).read_text(encoding="utf-8") == expected


def test_check_exits_nonzero_when_a_tracked_artifact_differs(tmp_path: Path) -> None:
    generated_path = tmp_path / "contracts/jsonschema/device-identity-v1.json"
    generated_path.parent.mkdir(parents=True)
    generated_path.write_text("{}\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "tools/contracts/generate_contract_artifacts.py",
            "--check",
            "--output-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "contracts/jsonschema/device-identity-v1.json" in result.stderr


def test_check_exits_nonzero_when_an_unexpected_generated_artifact_exists(
    tmp_path: Path,
) -> None:
    for relative_path, content in render_artifacts(tmp_path).items():
        destination = tmp_path / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    stale_path = tmp_path / "contracts/jsonschema/stale-v1.json"
    stale_path.write_text("{}\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "tools/contracts/generate_contract_artifacts.py",
            "--check",
            "--output-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "contracts/jsonschema/stale-v1.json" in result.stderr


def test_generated_openapi_has_only_resolvable_local_references(tmp_path: Path) -> None:
    rendered = render_artifacts(tmp_path)
    openapi = yaml.safe_load(
        rendered[Path("contracts/openapi/endpoint-platform-v1.yaml")]
    )

    assert isinstance(openapi, dict)
    local_refs = list(_walk_local_refs(openapi))
    assert local_refs
    for reference in local_refs:
        assert _resolve_json_pointer(openapi, reference) is not None


@pytest.mark.parametrize("filename", PUBLIC_MODELS)
def test_fixture_is_synthetic_and_contains_no_sensitive_values(filename: str) -> None:
    fixture = json.loads((Path("tests/fixtures/contracts") / filename).read_text(
        encoding="utf-8"
    ))

    _assert_synthetic_fixture(fixture)


@pytest.mark.parametrize(
    "unsafe_fixture",
    [
        {"metadata": {"refresh_token": "test-value"}},
        {"metadata": {"client_secret": "test-value"}},
        {"metadata": {"authorization": "Bearer example-value"}},
        {"metadata": {"value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signature"}},
        {"metadata": {"value": "A" * 32}},
        {"metadata": {"path": "/var/lib/endpoint/device.json"}},
        {"metadata": {"path": r"C:\\endpoint\\device.json"}},
        {"device_id": "99999999-9999-4999-8999-999999999999"},
        {"hardware_fingerprint": "prod-host-fingerprint"},
    ],
)
def test_synthetic_fixture_policy_rejects_sensitive_or_production_data(
    unsafe_fixture: dict[str, Any],
) -> None:
    with pytest.raises(AssertionError):
        _assert_synthetic_fixture(unsafe_fixture)
