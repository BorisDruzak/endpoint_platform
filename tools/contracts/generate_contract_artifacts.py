from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from endpoint_contracts import (  # noqa: E402
    AgentHelloV1,
    AgentBuildRecommendationV1,
    AgentCommandAckV1,
    AgentCommandV1,
    AgentEnrollmentDeliveryV1,
    AgentEnrollmentRequestV1,
    AgentHeartbeatV1,
    AgentResultV1,
    AgentSessionV1,
    DeviceIdentityV1,
    DeviceCredentialRotationV1,
    DeviceContextBaselineV1,
    DeviceContextDiagnosticV1,
    DeviceContextDiffV1,
    DeviceContextHealthV1,
    DeviceContextNetworkV1,
    EnrollmentDeliveryProofV1,
    EnrollmentRequestV1,
    EnrollmentResponseV1,
    GatewayHelloV1,
    GatewayWsEnvelopeV1,
    AgentUpdateAcknowledgementV1,
    AgentUpdateRecommendationV1,
    AgentUpdateReportV1,
    UpdateBuildManifestV1,
    UpdateRolloutCreateV1,
    EndpointDiagnosticResultV1,
    EndpointOperationCreateV1,
    EndpointOperationV1,
)
from endpoint_contracts.base import ContractModelV1  # noqa: E402


PUBLIC_MODELS: dict[str, type[ContractModelV1]] = {
    "device-identity-v1.json": DeviceIdentityV1,
    "agent-session-v1.json": AgentSessionV1,
    "enrollment-request-v1.json": EnrollmentRequestV1,
    "enrollment-response-v1.json": EnrollmentResponseV1,
    "agent-enrollment-request-v1.json": AgentEnrollmentRequestV1,
    "agent-enrollment-delivery-v1.json": AgentEnrollmentDeliveryV1,
    "enrollment-delivery-proof-v1.json": EnrollmentDeliveryProofV1,
    "device-credential-rotation-v1.json": DeviceCredentialRotationV1,
    "agent-command-v1.json": AgentCommandV1,
    "agent-command-ack-v1.json": AgentCommandAckV1,
    "agent-result-v1.json": AgentResultV1,
    "agent-heartbeat-v1.json": AgentHeartbeatV1,
    "agent-build-recommendation-v1.json": AgentBuildRecommendationV1,
    "update-build-manifest-v1.json": UpdateBuildManifestV1,
    "update-rollout-v1.json": UpdateRolloutCreateV1,
    "agent-update-recommendation-v1.json": AgentUpdateRecommendationV1,
    "agent-update-ack-v1.json": AgentUpdateAcknowledgementV1,
    "agent-update-report-v1.json": AgentUpdateReportV1,
    "device_context_baseline_v1.json": DeviceContextBaselineV1,
    "device_context_health_v1.json": DeviceContextHealthV1,
    "device_context_network_v1.json": DeviceContextNetworkV1,
    "device_context_diagnostic_v1.json": DeviceContextDiagnosticV1,
    "device_context_diff_v1.json": DeviceContextDiffV1,
    "endpoint-operation-create-v1.json": EndpointOperationCreateV1,
    "endpoint-operation-v1.json": EndpointOperationV1,
    "endpoint-operation-diagnostic-result-v1.json": EndpointDiagnosticResultV1,
}

GATEWAY_WS_MODELS: dict[str, type[BaseModel]] = {
    "agent_hello_v1.json": AgentHelloV1,
    "gateway_hello_v1.json": GatewayHelloV1,
    "gateway_ws_envelope_v1.json": GatewayWsEnvelopeV1,
}

FIXTURES: dict[str, dict[str, Any]] = {
    "device-identity-v1.json": {
        "schema_version": "device_identity_v1",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "platform": "linux",
        "hardware_fingerprint": "sha256:fixture-hardware-fingerprint-01",
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
        "hardware_fingerprint": "sha256:fixture-hardware-fingerprint-01",
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
    "update-build-manifest-v1.json": {
        "schema_version": "update_build_manifest_v1",
        "build_identifier": "endpoint-agent-linux-1.2.3",
        "version": "1.2.3",
        "platform": "linux_amd64",
        "channel": "stable",
        "artifact_url": "https://releases.example.test/endpoint-agent-1.2.3.tar.gz",
        "artifact_name": "endpoint-agent-1.2.3.tar.gz",
        "archive_type": "tar.gz",
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "size": 1024,
        "release_notes": "Fixture release notes.",
    },
    "update-rollout-v1.json": {
        "schema_version": "update_rollout_v1",
        "build_identifier": "endpoint-agent-linux-1.2.3",
        "mode": "canary",
        "device_ids": ["11111111-1111-4111-8111-111111111111"],
        "reason": "Fixture canary rollout.",
    },
    "agent-update-recommendation-v1.json": {
        "schema_version": "agent_update_recommendation_v1",
        "operation_id": "44444444-4444-4444-8444-444444444444",
        "build_identifier": "endpoint-agent-linux-1.2.3",
        "version": "1.2.3",
        "platform": "linux_amd64",
        "channel": "stable",
        "artifact_url": "https://releases.example.test/endpoint-agent-1.2.3.tar.gz",
        "artifact_name": "endpoint-agent-1.2.3.tar.gz",
        "archive_type": "tar.gz",
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "size": 1024,
        "reason": "Fixture canary rollout.",
    },
    "agent-update-ack-v1.json": {
        "schema_version": "agent_update_ack_v1",
        "status": "scheduled",
    },
    "agent-update-report-v1.json": {
        "schema_version": "agent_update_report_v1",
        "report_key": "report-fixture-01",
        "status": "applied",
        "reported_version": "1.2.3",
        "safe_code": "post_restart_handshake",
    },
}

GATEWAY_WS_FIXTURES: dict[str, dict[str, Any]] = {
    "agent_hello_v1.json": {
        "schema_version": "agent_hello_v1",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "agent_instance_id": "22222222-2222-4222-8222-222222222222",
        "agent_version": "4.0.0",
        "launcher_version": "2.1.0",
        "platform": "linux_amd64",
        "boot_id": "fixture-boot-01",
        "capabilities": [
            "context.baseline.collect",
            "context.health.collect",
        ],
        "last_result_sequence": 7,
        "last_policy_revision": 11,
    },
    "gateway_hello_v1.json": {
        "schema_version": "gateway_hello_v1",
        "session_id": "33333333-3333-4333-8333-333333333333",
        "heartbeat_interval_seconds": 30,
        "maximum_message_bytes": 65536,
        "policy_revision": 12,
        "effective_capabilities": ["context.baseline.collect"],
        "server_time": "2026-08-01T07:30:00Z",
    },
    "gateway_ws_envelope_v1.json": {
        "schema_version": "gateway_ws_envelope_v1",
        "kind": "command",
        "sequence": 1,
        "payload": {
            "schema_version": "agent_command_v1",
            "command_id": "44444444-4444-4444-8444-444444444444",
            "device_id": "11111111-1111-4111-8111-111111111111",
            "capability": "context.baseline.collect",
            "parameters": {},
            "requested_by_service": "endpoint-gateway",
            "idempotency_key": "gateway-command-01",
            "created_at": "2026-08-01T07:30:00Z",
            "deadline_at": "2026-08-01T07:35:00Z",
        },
    },
}

ENDPOINT_OPERATION_FIXTURES: dict[Path, dict[str, Any]] = {
    Path("endpoint-operation-create-v1.json"): {
        "schema_version": "endpoint_operation_create_v1",
        "capability": "context.diagnostic.collect",
        "parameters": {"reason": "Fixture diagnostic request."},
        "correlation": {
            "schema_version": "endpoint_operation_correlation_v1",
            "source_system": "helpdesk",
            "source_entity_type": "ticket",
            "source_entity_id": "fixture-ticket-01",
            "request_id": "33333333-3333-4333-8333-333333333333",
        },
    },
    Path("endpoint-operation-v1.json"): {
        "schema_version": "endpoint_operation_v1",
        "operation_id": "22222222-2222-4222-8222-222222222222",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "capability": "context.diagnostic.collect",
        "status": "succeeded",
        "created_at": "2026-08-09T11:59:00Z",
        "deadline_at": "2026-08-09T12:30:00Z",
        "completed_at": "2026-08-09T12:00:00Z",
        "correlation": {
            "schema_version": "endpoint_operation_correlation_v1",
            "source_system": "helpdesk",
            "source_entity_type": "ticket",
            "source_entity_id": "fixture-ticket-01",
            "request_id": "33333333-3333-4333-8333-333333333333",
        },
        "result_available": True,
        "warnings": ["redaction_applied"],
    },
    Path("endpoint-operation-diagnostic-result-v1.json"): {
        "schema_version": "endpoint_diagnostic_result_v1",
        "profile": "diagnostic_v1",
        "collected_at": "2026-08-09T12:00:00Z",
        "reason": "Fixture diagnostic request.",
        "warnings": ["redaction_applied"],
        "processes": [{"name": "fixture-process", "state": "running"}],
        "log_excerpt": "Fixture redacted diagnostic excerpt.",
    },
    Path("invalid/endpoint-operation-create-url-reason-v1.json"): {
        "schema_version": "endpoint_operation_create_v1",
        "capability": "context.diagnostic.collect",
        "parameters": {"reason": "https://untrusted.example.test/run"},
    },
}

GENERATED_ARTIFACT_DIRECTORIES = (
    Path("contracts/jsonschema"),
    Path("contracts/openapi"),
    Path("tests/fixtures/contracts"),
    Path("tests/fixtures/gateway_ws"),
    Path("tests/fixtures/endpoint_operations"),
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
                    lines.append(
                        f"{prefix}{rendered_key}: {{}}"
                        if isinstance(child, Mapping)
                        else f"{prefix}{rendered_key}: []"
                    )
                else:
                    lines.append(f"{prefix}{rendered_key}:")
                    lines.extend(
                        _yaml_document(child, indent=indent + 2)
                        .rstrip("\n")
                        .splitlines()
                    )
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
                    lines.append(
                        f"{prefix}- {{}}"
                        if isinstance(child, Mapping)
                        else f"{prefix}- []"
                    )
                else:
                    lines.append(f"{prefix}-")
                    lines.extend(
                        _yaml_document(child, indent=indent + 2)
                        .rstrip("\n")
                        .splitlines()
                    )
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


def _json_content(component_name: str) -> dict[str, object]:
    return {
        "application/json": {
            "schema": {"$ref": f"#/components/schemas/{component_name}"}
        }
    }


def _operation_response_content() -> dict[str, object]:
    return {
        "application/json": {
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["data"],
                "properties": {
                    "data": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["operation", "result"],
                        "properties": {
                            "operation": {
                                "$ref": "#/components/schemas/EndpointOperationV1"
                            },
                            "result": {
                                "anyOf": [
                                    {
                                        "$ref": (
                                            "#/components/schemas/"
                                            "EndpointDiagnosticResultV1"
                                        )
                                    },
                                    {"type": "null"},
                                ]
                            },
                        },
                    }
                },
            }
        }
    }


def _service_operation_paths() -> dict[str, object]:
    service_security = [{"ServiceBearer": []}]
    device_parameter = {
        "name": "device_id",
        "in": "path",
        "required": True,
        "schema": {"type": "string", "format": "uuid"},
    }
    operation_parameter = {
        "name": "operation_id",
        "in": "path",
        "required": True,
        "schema": {"type": "string", "format": "uuid"},
    }
    return {
        "/api/v1/devices/{device_id}/capabilities": {
            "get": {
                "security": service_security,
                "x-required-scopes": ["devices.read"],
                "parameters": [device_parameter],
                "responses": {
                    "200": {
                        "description": "Safe endpoint operation availability",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["data"],
                                    "properties": {
                                        "data": {
                                            "type": "object",
                                            "additionalProperties": False,
                                            "required": [
                                                "device_id",
                                                "capabilities",
                                            ],
                                            "properties": {
                                                "device_id": {
                                                    "type": "string",
                                                    "format": "uuid",
                                                },
                                                "capabilities": {
                                                    "type": "array",
                                                    "maxItems": 1,
                                                    "items": {
                                                        "type": "object",
                                                        "additionalProperties": False,
                                                        "required": [
                                                            "capability",
                                                            "available",
                                                        ],
                                                        "properties": {
                                                            "capability": {
                                                                "const": (
                                                                    "context."
                                                                    "diagnostic."
                                                                    "collect"
                                                                )
                                                            },
                                                            "available": {
                                                                "type": "boolean"
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        }
                                    },
                                }
                            }
                        },
                    },
                    "404": {"description": "Active device not found"},
                },
            }
        },
        "/api/v1/devices/{device_id}/operations": {
            "post": {
                "security": service_security,
                "x-required-scopes": ["operations.create"],
                "parameters": [
                    device_parameter,
                    {
                        "name": "Idempotency-Key",
                        "in": "header",
                        "required": True,
                        "schema": {
                            "type": "string",
                            "minLength": 8,
                            "maxLength": 128,
                        },
                    },
                ],
                "requestBody": {
                    "required": True,
                    "content": _json_content("EndpointOperationCreateV1"),
                },
                "responses": {
                    "200": {
                        "description": "Replayed endpoint operation",
                        "content": _operation_response_content(),
                    },
                    "201": {
                        "description": "Created endpoint operation",
                        "content": _operation_response_content(),
                    },
                    "409": {"description": "Idempotency key conflict"},
                    "422": {"description": "Invalid endpoint operation request"},
                    "503": {"description": "Safe result unavailable"},
                },
            }
        },
        "/api/v1/operations/{operation_id}": {
            "get": {
                "security": service_security,
                "x-required-scopes": ["operations.read"],
                "parameters": [operation_parameter],
                "responses": {
                    "200": {
                        "description": "Safe endpoint operation projection",
                        "content": _operation_response_content(),
                    },
                    "404": {"description": "Endpoint operation not found"},
                    "503": {"description": "Safe result unavailable"},
                },
            }
        },
    }


def _agent_http_paths() -> dict[str, object]:
    bearer_security = [{"AgentBearer": []}]
    return {
        "/agent/v1/enroll": {
            "post": {
                "security": bearer_security,
                "requestBody": {
                    "required": True,
                    "content": _json_content("AgentEnrollmentRequestV1"),
                },
                "responses": {
                    "200": {
                        "description": "Recovered committed enrollment delivery",
                        "content": _json_content("AgentEnrollmentDeliveryV1"),
                    },
                    "201": {
                        "description": "Created enrollment delivery",
                        "content": _json_content("AgentEnrollmentDeliveryV1"),
                    },
                },
            }
        },
        "/agent/v1/enroll/retry": {
            "post": {
                "requestBody": {
                    "required": True,
                    "content": _json_content("EnrollmentDeliveryProofV1"),
                },
                "responses": {
                    "200": {
                        "description": "Recovered unacknowledged delivery",
                        "content": _json_content("AgentEnrollmentDeliveryV1"),
                    }
                },
            }
        },
        "/agent/v1/enroll/ack": {
            "post": {
                "requestBody": {
                    "required": True,
                    "content": _json_content("EnrollmentDeliveryProofV1"),
                },
                "responses": {
                    "204": {"description": "Enrollment delivery acknowledged"}
                },
            }
        },
        "/agent/v1/credentials/rotate": {
            "post": {
                "security": bearer_security,
                "responses": {
                    "201": {
                        "description": "Created pending device credential",
                        "content": _json_content("DeviceCredentialRotationV1"),
                    }
                },
            }
        },
        "/agent/v1/credentials/activate": {
            "post": {
                "security": bearer_security,
                "responses": {"204": {"description": "Pending credential activated"}},
            }
        },
        "/agent/v1/updates/recommendation": {
            "get": {
                "security": bearer_security,
                "parameters": [
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
                ],
                "responses": {
                    "200": {
                        "description": "Active update recommendation",
                        "content": _json_content("AgentUpdateRecommendationV1"),
                    },
                    "204": {"description": "No active update assignment"},
                },
            }
        },
        "/agent/v1/updates/{operation_id}/ack": {
            "post": {
                "security": bearer_security,
                "parameters": [
                    {
                        "name": "operation_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": _json_content("AgentUpdateAcknowledgementV1"),
                },
                "responses": {
                    "204": {"description": "Update acknowledgement recorded"}
                },
            }
        },
        "/agent/v1/updates/{operation_id}/reports": {
            "post": {
                "security": bearer_security,
                "parameters": [
                    {
                        "name": "operation_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": _json_content("AgentUpdateReportV1"),
                },
                "responses": {"200": {"description": "Update report recorded"}},
            }
        },
        **_service_operation_paths(),
    }


def render_artifacts(output_root: Path) -> dict[Path, str]:
    """Return every generated artifact without writing to *output_root*."""
    _ = output_root
    rendered: dict[Path, str] = {}
    schemas = {
        filename: _annotate_model_only_timestamp_normalization(
            model.model_json_schema()
        )
        for filename, model in PUBLIC_MODELS.items()
    }
    for filename, schema in schemas.items():
        rendered[Path("contracts/jsonschema") / filename] = _json_document(schema)

    gateway_ws_schemas = {
        filename: _annotate_model_only_timestamp_normalization(
            model.model_json_schema()
        )
        for filename, model in GATEWAY_WS_MODELS.items()
    }
    for filename, schema in gateway_ws_schemas.items():
        rendered[Path("contracts/jsonschema") / filename] = _json_document(schema)

    openapi = {
        "openapi": "3.1.0",
        "info": {"title": "Endpoint Platform API", "version": "v1"},
        "paths": _agent_http_paths(),
        "components": {
            "schemas": _openapi_component_schemas(schemas),
            "securitySchemes": {
                "AgentBearer": {
                    "type": "http",
                    "scheme": "bearer",
                },
                "ServiceBearer": {
                    "type": "http",
                    "scheme": "bearer",
                },
            },
        },
    }
    rendered[Path("contracts/openapi/endpoint-platform-v1.yaml")] = _yaml_document(
        openapi
    )

    for filename, fixture in FIXTURES.items():
        rendered[Path("tests/fixtures/contracts") / filename] = _json_document(fixture)
    for filename, fixture in GATEWAY_WS_FIXTURES.items():
        rendered[Path("tests/fixtures/gateway_ws") / filename] = _json_document(fixture)
    for relative_path, fixture in ENDPOINT_OPERATION_FIXTURES.items():
        rendered[Path("tests/fixtures/endpoint_operations") / relative_path] = (
            _json_document(fixture)
        )
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
        actual = (
            destination.read_text(encoding="utf-8") if destination.exists() else None
        )
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
    action.add_argument(
        "--write", action="store_true", help="write generated artifacts"
    )
    action.add_argument(
        "--check", action="store_true", help="check generated artifacts"
    )
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
