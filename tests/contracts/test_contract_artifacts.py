import json
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from endpoint_contracts import AgentCommandV1
from tools.contracts.generate_contract_artifacts import (
    FIXTURES,
    PUBLIC_MODELS,
    render_artifacts,
)


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
DEVICE_DATA_FIELDS = {
    "serial_number",
    "mac_address",
    "asset_tag",
    "bios_uuid",
    "fqdn",
}


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


def _contains_url_credentials(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return True
    return (
        parsed.username is not None
        or parsed.password is not None
        or any(SENSITIVE_KEY_PATTERN.search(key) for key, _ in parse_qsl(parsed.query))
    )


def _assert_synthetic_fixture(value: Any) -> None:
    for path, child in _walk_json(value):
        field_name = path[-1]
        assert not SENSITIVE_KEY_PATTERN.search(field_name), path
        if not isinstance(child, str):
            continue
        assert not SENSITIVE_VALUE_PATTERN.search(child), path
        assert not ABSOLUTE_PATH_PATTERN.search(child), path
        assert not _contains_url_credentials(child), path
        if UUID_PATTERN.fullmatch(child):
            assert child in SYNTHETIC_UUIDS, path
        elif field_name != "sha256":
            assert not OPAQUE_VALUE_PATTERN.fullmatch(child), path
        if (
            field_name.lower() in DEVICE_DATA_FIELDS
            or any(marker in field_name.lower() for marker in DEVICE_DATA_MARKERS)
        ):
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


def _schema_validator(filename: str) -> Draft202012Validator:
    schema = json.loads(
        (Path("contracts/jsonschema") / filename).read_text(encoding="utf-8")
    )
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _openapi_component_validator(component_name: str) -> Draft202012Validator:
    openapi = yaml.safe_load(
        Path("contracts/openapi/endpoint-platform-v1.yaml").read_text(
            encoding="utf-8"
        )
    )
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": f"#/components/schemas/{component_name}",
        "components": openapi["components"],
    }
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


@pytest.mark.parametrize("filename", PUBLIC_MODELS)
def test_fixture_validates_against_model_and_schema(filename: str) -> None:
    fixture = json.loads(
        (Path("tests/fixtures/contracts") / filename).read_text(encoding="utf-8")
    )
    schema = json.loads(
        (Path("contracts/jsonschema") / filename).read_text(encoding="utf-8")
    )

    PUBLIC_MODELS[filename].model_validate(fixture)
    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(fixture)


@pytest.mark.parametrize(
    "capability",
    ["shell.execute", "python", "powershell", "routeros", "scheme", "custom.action"],
)
def test_agent_command_schema_rejects_unallowlisted_capabilities(
    capability: str,
) -> None:
    fixture = dict(FIXTURES["agent-command-v1.json"])
    fixture["capability"] = capability

    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("agent-command-v1.json").validate(fixture)


@pytest.mark.parametrize(
    "parameters",
    [
        {"nested": {"message": "x" * 4097}},
        {"nested": {"items": list(range(33))}},
        {"nested": {f"key-{index}": index for index in range(33)}},
    ],
)
def test_agent_command_schema_rejects_nested_json_container_bounds(
    parameters: dict[str, object],
) -> None:
    fixture = dict(FIXTURES["agent-command-v1.json"])
    fixture["parameters"] = parameters

    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("agent-command-v1.json").validate(fixture)


def test_agent_command_schema_rejects_json_beyond_maximum_depth() -> None:
    nested: object = "leaf"
    for _ in range(9):
        nested = [nested]
    fixture = dict(FIXTURES["agent-command-v1.json"])
    fixture["parameters"] = {"nested": nested}

    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("agent-command-v1.json").validate(fixture)


@pytest.mark.parametrize(
    "artifact_path",
    [
        "/var/lib/endpoint/agent.tar.gz",
        r"C:\endpoint\agent.zip",
        "../agent/agent.tar.gz",
        "agent/../agent.tar.gz",
    ],
)
def test_build_recommendation_schema_rejects_non_relative_artifact_paths(
    artifact_path: str,
) -> None:
    fixture = dict(FIXTURES["agent-build-recommendation-v1.json"])
    fixture["artifact_path"] = artifact_path

    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("agent-build-recommendation-v1.json").validate(fixture)


def test_agent_command_schema_documents_model_only_aggregate_rules() -> None:
    schema = json.loads(
        Path("contracts/jsonschema/agent-command-v1.json").read_text(encoding="utf-8")
    )
    fixture = dict(FIXTURES["agent-command-v1.json"])
    fixture["deadline_at"] = fixture["created_at"]

    Draft202012Validator(schema).validate(fixture)
    with pytest.raises(PydanticValidationError):
        AgentCommandV1.model_validate(fixture)

    assert "deadline_at" in schema["$comment"]
    assert "node count" in schema["properties"]["parameters"]["$comment"]
    assert "serialized byte size" in schema["properties"]["parameters"]["$comment"]


@pytest.mark.parametrize(
    ("component_name", "fixture_name", "overrides"),
    [
        (
            "AgentCommandV1",
            "agent-command-v1.json",
            {"capability": "shell.execute"},
        ),
        (
            "AgentCommandV1",
            "agent-command-v1.json",
            {"parameters": {"nested": {"message": "x" * 4097}}},
        ),
        (
            "AgentBuildRecommendationV1",
            "agent-build-recommendation-v1.json",
            {"artifact_path": "../agent/agent.zip"},
        ),
    ],
)
def test_openapi_components_enforce_expressible_contract_constraints(
    component_name: str,
    fixture_name: str,
    overrides: dict[str, object],
) -> None:
    fixture = {**FIXTURES[fixture_name], **overrides}

    with pytest.raises(JsonSchemaValidationError):
        _openapi_component_validator(component_name).validate(fixture)


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
        {"metadata": {"url": "https://fixture-user:fixture-pass@example.test/artifact"}},
        {"metadata": {"url": "https://example.test/artifact?access_token=fixture-value"}},
        {"metadata": {"url": "https://["}},
        {"device_id": "99999999-9999-4999-8999-999999999999"},
        {"hardware_fingerprint": "prod-host-fingerprint"},
        {"serial_number": "ABC123"},
        {"mac_address": "00:11:22:33:44:55"},
        {"asset_tag": "RACK-7"},
        {"bios_uuid": "55555555-5555-4555-8555-555555555555"},
        {"fqdn": "workstation.example.test"},
    ],
)
def test_synthetic_fixture_policy_rejects_sensitive_or_production_data(
    unsafe_fixture: dict[str, Any],
) -> None:
    with pytest.raises(AssertionError):
        _assert_synthetic_fixture(unsafe_fixture)
