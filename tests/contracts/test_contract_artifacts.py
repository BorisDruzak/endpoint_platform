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
from jsonschema import (
    Draft202012Validator,
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError as PydanticValidationError

from endpoint_contracts import (
    AgentCommandV1,
    AgentUpdateAcknowledgementV1,
    AgentUpdateRecommendationV1,
    AgentUpdateReportV1,
    AdapterListParametersV1,
    AdapterListResultV1,
    RouteGetParametersV1,
    RouteGetResultV1,
    ServiceStatusParametersV1,
    ServiceStatusResultV1,
    UpdateBuildManifestV1,
    UpdateRolloutCreateV1,
)
from endpoint_contracts.identity import normalize_install_session_id
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


def _walk_json(
    value: Any, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], Any]]:
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


def test_fixture_safety_allows_only_a_false_public_secret_marker() -> None:
    """Public non-secret metadata may state that a descriptor is never secret."""
    _assert_synthetic_fixture({"secret": False})
    for unsafe_value in (True, "redacted"):
        with pytest.raises(AssertionError):
            _assert_synthetic_fixture({"secret": unsafe_value})


def _assert_synthetic_fixture(value: Any) -> None:
    for path, child in _walk_json(value):
        field_name = path[-1]
        if field_name == "secret" and child is False:
            continue
        assert not SENSITIVE_KEY_PATTERN.search(field_name), path
        if not isinstance(child, str):
            continue
        assert not SENSITIVE_VALUE_PATTERN.search(child), path
        assert not ABSOLUTE_PATH_PATTERN.search(child), path
        assert not _contains_url_credentials(child), path
        if UUID_PATTERN.fullmatch(child):
            assert child in SYNTHETIC_UUIDS, path
        elif field_name not in {"sha256", "schema_version", "feature_flag"}:
            assert not OPAQUE_VALUE_PATTERN.fullmatch(child), path
        if field_name.lower() in DEVICE_DATA_FIELDS or any(
            marker in field_name.lower() for marker in DEVICE_DATA_MARKERS
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
        Path("contracts/openapi/endpoint-platform-v1.yaml").read_text(encoding="utf-8")
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


@pytest.mark.parametrize("filename", FIXTURES)
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
        "agent/agent.zip\n",
    ],
)
def test_build_recommendation_schema_rejects_non_relative_artifact_paths(
    artifact_path: str,
) -> None:
    fixture = dict(FIXTURES["agent-build-recommendation-v1.json"])
    fixture["artifact_path"] = artifact_path

    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("agent-build-recommendation-v1.json").validate(fixture)


def test_build_recommendation_schema_uses_ecma_strict_end_anchor() -> None:
    schema = json.loads(
        Path("contracts/jsonschema/agent-build-recommendation-v1.json").read_text(
            encoding="utf-8"
        )
    )
    pattern = schema["properties"]["artifact_path"]["pattern"]
    validator = _schema_validator("agent-build-recommendation-v1.json")

    assert pattern.endswith(r"(?![\s\S])")

    valid_fixture = dict(FIXTURES["agent-build-recommendation-v1.json"])
    valid_fixture["artifact_path"] = "releases/agent.tar.gz"
    validator.validate(valid_fixture)

    invalid_fixture = dict(valid_fixture)
    invalid_fixture["artifact_path"] = "releases/agent.tar.gz\n"
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(invalid_fixture)


def test_every_generated_timestamp_schema_documents_utc_normalization() -> None:
    for filename in PUBLIC_MODELS:
        schema = json.loads(
            (Path("contracts/jsonschema") / filename).read_text(encoding="utf-8")
        )
        timestamps = [
            value
            for _, value in _walk_json(schema)
            if isinstance(value, dict) and value.get("format") == "date-time"
        ]
        for timestamp in timestamps:
            assert "model-only UTC normalization" in timestamp["$comment"]


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


def test_hardware_fingerprint_schemas_publish_canonical_shape() -> None:
    """Provisioning and agent clients must share the same public proof grammar."""
    expected = r"^sha256:[a-z0-9][a-z0-9._-]{1,248}$"
    for filename in (
        "device-identity-v1.json",
        "enrollment-request-v1.json",
        "agent-enrollment-request-v1.json",
        "enrollment-delivery-proof-v1.json",
    ):
        schema = json.loads(
            (Path("contracts/jsonschema") / filename).read_text(encoding="utf-8")
        )
        assert schema["properties"]["hardware_fingerprint"]["pattern"] == expected


@pytest.mark.parametrize(
    "value",
    ["alt-install-001", "fixture_session.1", "x" * 128],
)
def test_install_session_contract_accepts_bounded_printable_ascii(value: str) -> None:
    assert normalize_install_session_id(value) == value


@pytest.mark.parametrize(
    "value",
    ["", " bad", "bad ", "line\nbreak", "не-ascii", "x" * 129],
)
def test_install_session_contract_rejects_unsafe_or_unbounded_values(
    value: str,
) -> None:
    with pytest.raises(ValueError):
        normalize_install_session_id(value)


def test_committed_contract_artifacts_match_renderer_without_mutation(
    tmp_path: Path,
) -> None:
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


def test_secret_agent_transport_is_published_without_golden_credentials(
    tmp_path: Path,
) -> None:
    rendered = render_artifacts(tmp_path)
    secret_schema_names = {
        "agent-enrollment-request-v1.json",
        "agent-enrollment-delivery-v1.json",
        "enrollment-delivery-proof-v1.json",
        "device-credential-rotation-v1.json",
    }
    openapi = yaml.safe_load(
        rendered[Path("contracts/openapi/endpoint-platform-v1.yaml")]
    )

    assert secret_schema_names <= set(PUBLIC_MODELS)
    assert secret_schema_names.isdisjoint(FIXTURES)
    for filename in secret_schema_names:
        assert Path("contracts/jsonschema") / filename in rendered
        assert Path("tests/fixtures/contracts") / filename not in rendered
    assert {
        "/agent/v1/enroll",
        "/agent/v1/enroll/retry",
        "/agent/v1/enroll/ack",
        "/agent/v1/credentials/rotate",
        "/agent/v1/credentials/activate",
    } <= set(openapi["paths"])
    assert (
        openapi["paths"]["/agent/v1/enroll"]["post"]["responses"]["201"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "#/components/schemas/AgentEnrollmentDeliveryV1"
    )
    assert (
        openapi["paths"]["/agent/v1/enroll"]["post"]["requestBody"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "#/components/schemas/AgentEnrollmentRequestV1"
    )


def test_endpoint_operation_service_openapi_documents_scopes_and_safe_models(
    tmp_path: Path,
) -> None:
    """Published service routes must name scopes without exposing private models."""
    openapi = yaml.safe_load(
        render_artifacts(tmp_path)[
            Path("contracts/openapi/endpoint-platform-v1.yaml")
        ]
    )
    paths = openapi["paths"]
    capabilities = paths["/api/v1/devices/{device_id}/capabilities"]["get"]
    create = paths["/api/v1/devices/{device_id}/operations"]["post"]
    read = paths["/api/v1/operations/{operation_id}"]["get"]
    cancel = paths["/api/v1/operations/{operation_id}/cancel"]["post"]
    module_capabilities = paths["/api/v1/module-capabilities"]["get"]

    assert capabilities["security"] == [{"ServiceBearer": []}]
    assert capabilities["x-required-scopes"] == ["devices.read"]
    assert create["security"] == [{"ServiceBearer": []}]
    assert create["x-required-scopes"] == ["operations.create"]
    assert read["security"] == [{"ServiceBearer": []}]
    assert read["x-required-scopes"] == ["operations.read"]
    assert cancel["security"] == [{"ServiceBearer": []}]
    assert cancel["x-required-scopes"] == ["operations.cancel"]
    assert "409" in cancel["responses"]
    assert module_capabilities["security"] == [{"ServiceBearer": []}]
    assert module_capabilities["x-required-scopes"] == ["modules.read"]
    assert any(
        parameter["name"] == "Idempotency-Key" and parameter["required"] is True
        for parameter in create["parameters"]
    )
    assert (
        create["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        == "#/components/schemas/EndpointOperationCreateV1"
    )
    response_text = json.dumps(
        {
            "create": create["responses"],
            "read": read["responses"],
            "envelope": openapi["components"]["schemas"][
                "OperationResponseEnvelope"
            ],
            "data": openapi["components"]["schemas"]["OperationResponseData"],
        },
        sort_keys=True,
    )
    assert "EndpointOperationV1" in response_text
    assert "EndpointDiagnosticResultV1" in response_text
    for private_name in (
        "ContextCollection",
        "CommandResult",
        "ServiceCredential",
        "raw_payload",
        "raw_result_payload",
    ):
        assert private_name not in response_text


def test_agent_response_schemas_require_every_canonical_wire_field() -> None:
    """Defaults must not make mandatory discriminator or policy fields optional."""
    delivery = json.loads(
        Path("contracts/jsonschema/agent-enrollment-delivery-v1.json").read_text(
            encoding="utf-8"
        )
    )
    rotation = json.loads(
        Path("contracts/jsonschema/device-credential-rotation-v1.json").read_text(
            encoding="utf-8"
        )
    )

    assert set(delivery["required"]) == {
        "schema_version",
        "device_id",
        "policy_id",
        "policy",
        "enrollment_receipt",
        "device_token",
        "issued_at",
    }
    assert set(rotation["required"]) == {
        "schema_version",
        "device_token",
        "overlap_expires_at",
    }


def test_update_contract_artifacts_publish_strict_safe_control_plane_schemas() -> None:
    """Generated update schemas preserve immutable metadata and omit diagnostics."""
    expected_models = {
        "update-build-manifest-v1.json": UpdateBuildManifestV1,
        "update-rollout-v1.json": UpdateRolloutCreateV1,
        "agent-update-recommendation-v1.json": AgentUpdateRecommendationV1,
        "agent-update-ack-v1.json": AgentUpdateAcknowledgementV1,
        "agent-update-report-v1.json": AgentUpdateReportV1,
    }
    report_schema = json.loads(
        Path("contracts/jsonschema/agent-update-report-v1.json").read_text(
            encoding="utf-8"
        )
    )

    assert {name: PUBLIC_MODELS[name] for name in expected_models} == expected_models
    assert set(report_schema["required"]) == {
        "schema_version",
        "report_key",
        "status",
        "reported_version",
    }
    assert "traceback" not in report_schema["properties"]
    assert "logs" not in report_schema["properties"]
    assert "safe_message" not in report_schema["properties"]
    manifest_schema = json.loads(
        Path("contracts/jsonschema/update-build-manifest-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest_schema["properties"]["sha256"]["pattern"].endswith(r"(?![\s\S])")
    assert report_schema["properties"]["report_key"]["pattern"].endswith(r"(?![\s\S])")
    assert "model-only" in manifest_schema["$comment"].lower()
    assert "release_notes" in manifest_schema["$comment"]
    assert "credential" in manifest_schema["$comment"].lower()

    rollout_schema = json.loads(
        Path("contracts/jsonschema/update-rollout-v1.json").read_text(encoding="utf-8")
    )
    assert rollout_schema["properties"]["device_ids"]["uniqueItems"] is True
    assert "model-only" in rollout_schema["$comment"].lower()

    openapi = yaml.safe_load(
        Path("contracts/openapi/endpoint-platform-v1.yaml").read_text(encoding="utf-8")
    )
    assert {
        "/agent/v1/updates/recommendation",
        "/agent/v1/updates/{operation_id}/ack",
        "/agent/v1/updates/{operation_id}/reports",
    } <= set(openapi["paths"])
    recommendation_parameters = openapi["paths"]["/agent/v1/updates/recommendation"][
        "get"
    ]["parameters"]
    assert recommendation_parameters == [
        {
            "name": "platform",
            "in": "query",
            "required": True,
            "schema": {
                "type": "string",
                "enum": ["linux_amd64", "windows_amd64"],
            },
        },
        {
            "name": "channel",
            "in": "query",
            "required": True,
            "schema": {
                "type": "string",
                "enum": ["stable", "canary"],
            },
        },
    ]
    ack_success = openapi["paths"]["/agent/v1/updates/{operation_id}/ack"]["post"][
        "responses"
    ]["204"]
    report_success = openapi["paths"]["/agent/v1/updates/{operation_id}/reports"][
        "post"
    ]["responses"]["200"]
    assert ack_success == {"description": "Update acknowledgement recorded"}
    assert report_success == {"description": "Update report recorded"}


def test_read_only_primitive_contract_artifacts_publish_repaired_dtos() -> None:
    expected_models = {
        "route-get-parameters-v1.json": RouteGetParametersV1,
        "route-get-result-v1.json": RouteGetResultV1,
        "adapter-list-parameters-v1.json": AdapterListParametersV1,
        "adapter-list-result-v1.json": AdapterListResultV1,
        "service-status-parameters-v1.json": ServiceStatusParametersV1,
        "service-status-result-v1.json": ServiceStatusResultV1,
    }

    assert {name: PUBLIC_MODELS[name] for name in expected_models} == expected_models


@pytest.mark.parametrize(
    "artifact_url",
    [
        "http://bad.example.test/agent.tar.gz",
        "https://user:pass@example.test/agent.tar.gz",
        "https://example.test/agent.tar.gz#fragment",
        "https://example.test/agent.tar.gz?access_token=fixture-value",
        "https://example.test/agent.tar.gz?download=1",
        "https://example.test/agent.tar.gz?",
        "https://example.test/agent.tar.gz#",
        "https://example.test/agent.tar.gz?#",
        "https://user%40example.test/agent.tar.gz",
    ],
)
def test_manifest_schema_and_openapi_reject_noncanonical_artifact_urls(
    artifact_url: str,
) -> None:
    """Expose only canonical immutable HTTPS URLs through public schemas."""
    payload = {
        **FIXTURES["update-build-manifest-v1.json"],
        "artifact_url": artifact_url,
    }

    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("update-build-manifest-v1.json").validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        _openapi_component_validator("UpdateBuildManifestV1").validate(payload)


def test_manifest_schema_and_openapi_accept_case_insensitive_https_scheme() -> None:
    """Treat the URL scheme per interoperable URL syntax, not input casing."""
    payload = {
        **FIXTURES["update-build-manifest-v1.json"],
        "artifact_url": "HTTPS://releases.example.test/endpoint-agent-1.2.3.tar.gz",
    }

    _schema_validator("update-build-manifest-v1.json").validate(payload)
    _openapi_component_validator("UpdateBuildManifestV1").validate(payload)


@pytest.mark.parametrize("size", [True, "1"])
def test_manifest_schema_rejects_noninteger_sizes(size: object) -> None:
    """Keep immutable artifact size type strict in public JSON Schema."""
    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("update-build-manifest-v1.json").validate(
            {**FIXTURES["update-build-manifest-v1.json"], "size": size}
        )


@pytest.mark.parametrize("version", ["1.2.3-01", "1.2.3-01.1", "1.2.3-1.01"])
def test_manifest_schema_and_openapi_reject_invalid_semver_prereleases(
    version: str,
) -> None:
    """Keep SemVer prerelease validity aligned across published consumers."""
    payload = {**FIXTURES["update-build-manifest-v1.json"], "version": version}

    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("update-build-manifest-v1.json").validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        _openapi_component_validator("UpdateBuildManifestV1").validate(payload)


def test_rollout_schema_rejects_duplicate_device_targets() -> None:
    """Publish the same explicit-target uniqueness invariant as the model."""
    duplicate = "11111111-1111-4111-8111-111111111111"
    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("update-rollout-v1.json").validate(
            {
                **FIXTURES["update-rollout-v1.json"],
                "device_ids": [duplicate, duplicate],
            }
        )


def test_rollout_schema_rejects_uppercase_device_uuid() -> None:
    """Keep public target uniqueness semantics free of UUID case folding."""
    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("update-rollout-v1.json").validate(
            {
                **FIXTURES["update-rollout-v1.json"],
                "device_ids": ["AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"],
            }
        )


@pytest.mark.parametrize("filename", FIXTURES)
def test_fixture_is_synthetic_and_contains_no_sensitive_values(filename: str) -> None:
    fixture = json.loads(
        (Path("tests/fixtures/contracts") / filename).read_text(encoding="utf-8")
    )

    _assert_synthetic_fixture(fixture)


@pytest.mark.parametrize(
    "unsafe_fixture",
    [
        {"metadata": {"refresh_token": "test-value"}},
        {"metadata": {"client_secret": "test-value"}},
        {"metadata": {"authorization": "Bearer example-value"}},
        {
            "metadata": {
                "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signature"
            }
        },
        {"metadata": {"value": "A" * 32}},
        {"metadata": {"path": "/var/lib/endpoint/device.json"}},
        {"metadata": {"path": r"C:\\endpoint\\device.json"}},
        {
            "metadata": {
                "url": "https://fixture-user:fixture-pass@example.test/artifact"
            }
        },
        {
            "metadata": {
                "url": "https://example.test/artifact?access_token=fixture-value"
            }
        },
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
