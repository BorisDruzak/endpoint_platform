from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from endpoint_contracts import (
    AgentBuildRecommendationV1,
    AgentCommandAckV1,
    AgentCommandV1,
    AgentHeartbeatV1,
    AgentResultV1,
    AgentSessionV1,
    DeviceIdentityV1,
    EnrollmentRequestV1,
    EnrollmentResponseV1,
)
from endpoint_contracts.base import ContractModelV1


PUBLIC_MODELS: dict[str, type[ContractModelV1]] = {
    "device-identity-v1.json": DeviceIdentityV1,
    "agent-session-v1.json": AgentSessionV1,
    "enrollment-request-v1.json": EnrollmentRequestV1,
    "enrollment-response-v1.json": EnrollmentResponseV1,
    "agent-command-v1.json": AgentCommandV1,
    "agent-command-ack-v1.json": AgentCommandAckV1,
    "agent-result-v1.json": AgentResultV1,
    "agent-heartbeat-v1.json": AgentHeartbeatV1,
    "agent-build-recommendation-v1.json": AgentBuildRecommendationV1,
}

FIXTURES: dict[str, dict[str, Any]] = {
    "device-identity-v1.json": {
        "schema_version": "device_identity_v1",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "platform": "linux",
        "hardware_fingerprint": "fixture-hardware-fingerprint-01",
    },
    "agent-session-v1.json": {
        "schema_version": "agent_session_v1",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "session_id": "22222222-2222-4222-8222-222222222222",
        "issued_at": "2026-07-28T12:00:00Z",
        "expires_at": "2026-07-28T12:05:00Z",
    },
    "enrollment-request-v1.json": {
        "schema_version": "enrollment_request_v1",
        "platform": "linux",
        "hardware_fingerprint": "fixture-hardware-fingerprint-01",
        "installation_id": "fixture-installation-01",
        "requested_at": "2026-07-28T12:00:00Z",
    },
    "enrollment-response-v1.json": {
        "schema_version": "enrollment_response_v1",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "policy_id": "fixture-policy-01",
        "enrollment_receipt": "fixture-receipt-01",
        "issued_at": "2026-07-28T12:00:00Z",
    },
    "agent-command-v1.json": {
        "schema_version": "agent_command_v1",
        "command_id": "33333333-3333-4333-8333-333333333333",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "capability": "agent.status.read",
        "parameters": {"include": ["version", "uptime"]},
        "requested_by_service": "fixture-service",
        "idempotency_key": "fixture-command-01",
        "created_at": "2026-07-28T12:00:00Z",
        "deadline_at": "2026-07-28T12:05:00Z",
        "correlation": {
            "schema_version": "command_correlation_v1",
            "request_id": "44444444-4444-4444-8444-444444444444",
        },
    },
    "agent-command-ack-v1.json": {
        "schema_version": "agent_command_ack_v1",
        "command_id": "33333333-3333-4333-8333-333333333333",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "status": "acknowledged",
        "acknowledged_at": "2026-07-28T12:00:00Z",
        "message": "Fixture command acknowledged.",
    },
    "agent-result-v1.json": {
        "schema_version": "agent_result_v1",
        "command_id": "33333333-3333-4333-8333-333333333333",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "status": "succeeded",
        "result_items": [{"summary": "Fixture status result."}],
        "message": "Fixture command completed.",
        "completed_at": "2026-07-28T12:00:00Z",
    },
    "agent-heartbeat-v1.json": {
        "schema_version": "agent_heartbeat_v1",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "platform": "linux",
        "agent_version": "1.2.3-fixture",
        "reported_at": "2026-07-28T12:00:00Z",
    },
    "agent-build-recommendation-v1.json": {
        "schema_version": "agent_build_recommendation_v1",
        "version": "1.2.3-fixture",
        "platform": "linux",
        "artifact_path": "agent/linux/endpoint-agent-1.2.3-fixture.tar.gz",
        "artifact_size_bytes": 1024,
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "minimum_launcher_version": "1.0.0",
        "channel": "stable",
        "archive_type": "tar.gz",
        "issued_at": "2026-07-28T12:00:00Z",
    },
}

GENERATED_ARTIFACT_DIRECTORIES = (
    Path("contracts/jsonschema"),
    Path("contracts/openapi"),
    Path("tests/fixtures/contracts"),
)

_PLAIN_YAML_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
UTC_NORMALIZATION_COMMENT = (
    "model-only UTC normalization: timezone-aware values are normalized to UTC."
)


def _json_document(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _yaml_scalar(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    raise TypeError(f"unsupported YAML scalar type: {type(value)!r}")


def _yaml_key(value: object) -> str:
    if isinstance(value, str) and _PLAIN_YAML_KEY.fullmatch(value):
        return value
    return _yaml_scalar(value)


def _yaml_document(value: object, *, indent: int = 0) -> str:
    prefix = " " * indent
    if isinstance(value, Mapping):
        if not value:
            return f"{prefix}{{}}\n"
        lines: list[str] = []
        for key, child in value.items():
            rendered_key = _yaml_key(key)
            if isinstance(child, Mapping) or isinstance(child, list):
                if not child:
                    lines.append(f"{prefix}{rendered_key}: {{}}" if isinstance(child, Mapping) else f"{prefix}{rendered_key}: []")
                else:
                    lines.append(f"{prefix}{rendered_key}:")
                    lines.extend(_yaml_document(child, indent=indent + 2).rstrip("\n").splitlines())
            else:
                lines.append(f"{prefix}{rendered_key}: {_yaml_scalar(child)}")
        return "\n".join(lines) + "\n"
    if isinstance(value, list):
        if not value:
            return f"{prefix}[]\n"
        lines = []
        for child in value:
            if isinstance(child, Mapping) or isinstance(child, list):
                if not child:
                    lines.append(f"{prefix}- {{}}" if isinstance(child, Mapping) else f"{prefix}- []")
                else:
                    lines.append(f"{prefix}-")
                    lines.extend(_yaml_document(child, indent=indent + 2).rstrip("\n").splitlines())
            else:
                lines.append(f"{prefix}- {_yaml_scalar(child)}")
        return "\n".join(lines) + "\n"
    return f"{prefix}{_yaml_scalar(value)}\n"


def _rewrite_local_definition_references(
    value: object, reference_map: Mapping[str, str]
) -> object:
    if isinstance(value, dict):
        return {
            key: reference_map.get(child, child)
            if key == "$ref" and isinstance(child, str)
            else _rewrite_local_definition_references(child, reference_map)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            _rewrite_local_definition_references(child, reference_map)
            for child in value
        ]
    return value


def _annotate_model_only_timestamp_normalization(value: object) -> object:
    if isinstance(value, dict):
        annotated = {
            key: _annotate_model_only_timestamp_normalization(child)
            for key, child in value.items()
        }
        if annotated.get("format") == "date-time":
            annotated["$comment"] = UTC_NORMALIZATION_COMMENT
        return annotated
    if isinstance(value, list):
        return [_annotate_model_only_timestamp_normalization(child) for child in value]
    return value


def _openapi_component_schemas(
    schemas: Mapping[str, dict[str, Any]],
) -> dict[str, object]:
    components: dict[str, object] = {}
    for filename, model in PUBLIC_MODELS.items():
        component_name = model.__name__
        schema = json.loads(json.dumps(schemas[filename]))
        definitions = schema.pop("$defs", {})
        reference_map = {
            f"#/$defs/{definition_name}": (
                f"#/components/schemas/{component_name}__{definition_name}"
            )
            for definition_name in definitions
        }
        components[component_name] = _rewrite_local_definition_references(
            schema, reference_map
        )
        for definition_name, definition in definitions.items():
            components[f"{component_name}__{definition_name}"] = (
                _rewrite_local_definition_references(definition, reference_map)
            )
    return components


def render_artifacts(output_root: Path) -> dict[Path, str]:
    """Return every generated artifact without writing to *output_root*."""
    _ = output_root
    rendered: dict[Path, str] = {}
    schemas = {
        filename: _annotate_model_only_timestamp_normalization(model.model_json_schema())
        for filename, model in PUBLIC_MODELS.items()
    }
    for filename, schema in schemas.items():
        rendered[Path("contracts/jsonschema") / filename] = _json_document(schema)

    openapi = {
        "openapi": "3.1.0",
        "info": {"title": "Endpoint Platform Gateway API", "version": "v1"},
        "paths": {},
        "components": {
            "schemas": _openapi_component_schemas(schemas)
        },
    }
    rendered[Path("contracts/openapi/endpoint-platform-v1.yaml")] = _yaml_document(openapi)

    for filename, fixture in FIXTURES.items():
        rendered[Path("tests/fixtures/contracts") / filename] = _json_document(fixture)
    return rendered


def _write_artifacts(output_root: Path, artifacts: Mapping[Path, str]) -> None:
    for relative_path, content in artifacts.items():
        destination = output_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")


def _check_artifacts(output_root: Path, artifacts: Mapping[Path, str]) -> bool:
    matches = True
    for relative_path, expected in artifacts.items():
        destination = output_root / relative_path
        actual = destination.read_text(encoding="utf-8") if destination.exists() else None
        if actual != expected:
            print(
                f"outdated generated artifact: {relative_path.as_posix()}",
                file=sys.stderr,
            )
            matches = False
    expected_paths = set(artifacts)
    for artifact_directory in GENERATED_ARTIFACT_DIRECTORIES:
        directory = output_root / artifact_directory
        if not directory.exists():
            continue
        for destination in directory.rglob("*"):
            if not destination.is_file():
                continue
            relative_path = destination.relative_to(output_root)
            if relative_path in expected_paths:
                continue
            print(
                f"unexpected generated artifact: {relative_path.as_posix()}",
                file=sys.stderr,
            )
            matches = False
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Render gateway contract artifacts.")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="write generated artifacts")
    action.add_argument("--check", action="store_true", help="check generated artifacts")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="repository root containing generated artifacts",
    )
    arguments = parser.parse_args()
    artifacts = render_artifacts(arguments.output_root)
    if arguments.write:
        _write_artifacts(arguments.output_root, artifacts)
        return 0
    return 0 if _check_artifacts(arguments.output_root, artifacts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
