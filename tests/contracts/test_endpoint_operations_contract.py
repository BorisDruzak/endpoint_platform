from __future__ import annotations

import importlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError


FIXTURE_ROOT = Path("tests/fixtures/endpoint_operations")
SCHEMA_ROOT = Path("contracts/jsonschema")
FORMAT_CHECKER = FormatChecker()
DEVICE_ID = "11111111-1111-4111-8111-111111111111"
OPERATION_ID = "22222222-2222-4222-8222-222222222222"
REQUEST_ID = "33333333-3333-4333-8333-333333333333"


def _contracts() -> Any:
    try:
        module = importlib.import_module("endpoint_contracts.operations")
    except ModuleNotFoundError:
        pytest.fail("endpoint_contracts.operations must define endpoint operation v1")
    for name in (
        "EndpointDiagnosticResultV1",
        "EndpointOperationCreateV1",
        "EndpointOperationStatusV1",
        "EndpointOperationV1",
    ):
        assert getattr(module, name, None) is not None, f"missing contract API: {name}"
    return module


def _schema_validator(schema_name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_ROOT / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FORMAT_CHECKER)


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def _create_request() -> dict[str, object]:
    return {
        "schema_version": "endpoint_operation_create_v1",
        "capability": "context.diagnostic.collect",
        "parameters": {"reason": "Fixture diagnostic request."},
        "correlation": {
            "schema_version": "endpoint_operation_correlation_v1",
            "source_system": "helpdesk",
            "source_entity_type": "ticket",
            "source_entity_id": "fixture-ticket-01",
            "request_id": REQUEST_ID,
        },
    }


def _result() -> dict[str, object]:
    return {
        "schema_version": "endpoint_diagnostic_result_v1",
        "profile": "diagnostic_v1",
        "collected_at": "2026-08-09T12:00:00Z",
        "reason": "Fixture diagnostic request.",
        "warnings": ["redaction_applied"],
        "processes": [{"name": "fixture-process", "state": "running"}],
        "log_excerpt": "Fixture redacted diagnostic excerpt.",
    }


def _operation() -> dict[str, object]:
    return {
        "schema_version": "endpoint_operation_v1",
        "operation_id": OPERATION_ID,
        "device_id": DEVICE_ID,
        "capability": "context.diagnostic.collect",
        "status": "succeeded",
        "created_at": "2026-08-09T11:59:00Z",
        "deadline_at": "2026-08-09T12:30:00Z",
        "completed_at": "2026-08-09T12:00:00Z",
        "correlation": _create_request()["correlation"],
        "result_available": True,
        "warnings": ["redaction_applied"],
    }


def test_create_rejects_extra_and_url_like_reason() -> None:
    contracts = _contracts()
    valid = _create_request()

    with pytest.raises(ValidationError):
        contracts.EndpointOperationCreateV1.model_validate({**valid, "extra": True})
    with pytest.raises(ValidationError):
        contracts.EndpointOperationCreateV1.model_validate(
            {**valid, "parameters": {"reason": "https://bad"}}
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("ticket_id", "ticket-1"),
        ("target_url", "https://untrusted.example.test/run"),
        ("executable", "powershell.exe"),
        ("arguments", ["-Command", "whoami"]),
    ],
)
def test_create_rejects_helpdesk_and_generic_execution_fields(
    field_name: str, value: object
) -> None:
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.EndpointOperationCreateV1.model_validate(
            {**_create_request(), field_name: value}
        )


@pytest.mark.parametrize(
    "reason",
    ["", "reason\nwith-control", "review ftp://untrusted.example.test/run", "x" * 257],
)
def test_create_rejects_unbounded_or_unsafe_reasons(reason: str) -> None:
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.EndpointOperationCreateV1.model_validate(
            {**_create_request(), "parameters": {"reason": reason}}
        )


def test_create_accepts_non_url_double_slash_reason() -> None:
    contracts = _contracts()
    request = {
        **_create_request(),
        "parameters": {"reason": "Fixture review // operator note."},
    }

    assert contracts.EndpointOperationCreateV1.model_validate(
        request
    ).parameters.reason == request["parameters"]["reason"]
    _schema_validator("endpoint-operation-create-v1.json").validate(request)


def test_operation_exposes_only_safe_projection() -> None:
    contracts = _contracts()
    operation = contracts.EndpointOperationV1.model_validate(_operation())

    assert operation.model_dump(mode="json", exclude_none=True) == _operation()
    with pytest.raises(ValidationError):
        contracts.EndpointOperationV1.model_validate(
            {**_operation(), "command_id": REQUEST_ID}
        )
    with pytest.raises(ValidationError):
        contracts.EndpointOperationV1.model_validate(
            {**_operation(), "result": _result()}
        )


def test_diagnostic_result_exposes_only_redacted_snapshot_fields() -> None:
    contracts = _contracts()
    result = contracts.EndpointDiagnosticResultV1.model_validate(_result())

    assert result.model_dump(mode="json", exclude_none=True) == _result()
    with pytest.raises(ValidationError):
        contracts.EndpointDiagnosticResultV1.model_validate(
            {**_result(), "raw_result": {}}
        )

    unsafe_excerpts = (
        "/var/log/endpoint/raw.log",
        r"C:\\endpoint\\raw.log",
        "Traceback (most recent call last): /srv/app/x.py",
        "Bearer tok_12345678",
    )
    for unsafe_excerpt in unsafe_excerpts:
        with pytest.raises(ValidationError):
            contracts.EndpointDiagnosticResultV1.model_validate(
                {**_result(), "log_excerpt": unsafe_excerpt}
            )
        with pytest.raises(JsonSchemaValidationError):
            _schema_validator("endpoint-operation-diagnostic-result-v1.json").validate(
                {**_result(), "log_excerpt": unsafe_excerpt}
            )


@pytest.mark.parametrize(
    "unsafe_excerpt",
    ["/tmp", "token: secretvalue", "secret=topsecret"],
)
def test_diagnostic_result_rejects_structural_leakage(
    unsafe_excerpt: str,
) -> None:
    contracts = _contracts()

    with pytest.raises(ValidationError):
        contracts.EndpointDiagnosticResultV1.model_validate(
            {**_result(), "log_excerpt": unsafe_excerpt}
        )
    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("endpoint-operation-diagnostic-result-v1.json").validate(
            {**_result(), "log_excerpt": unsafe_excerpt}
        )


@pytest.mark.parametrize(
    "redacted_excerpt",
    [
        "No traceback was retained; details were redacted.",
        "Bearer authentication was redacted.",
    ],
)
def test_diagnostic_result_allows_redaction_prose(redacted_excerpt: str) -> None:
    contracts = _contracts()
    payload = {**_result(), "log_excerpt": redacted_excerpt}

    assert contracts.EndpointDiagnosticResultV1.model_validate(
        payload
    ).log_excerpt == redacted_excerpt
    _schema_validator("endpoint-operation-diagnostic-result-v1.json").validate(
        payload
    )


@pytest.mark.parametrize(
    ("schema_name", "fixture_name", "model_name"),
    [
        (
            "endpoint-operation-create-v1.json",
            "endpoint-operation-create-v1.json",
            "EndpointOperationCreateV1",
        ),
        (
            "endpoint-operation-v1.json",
            "endpoint-operation-v1.json",
            "EndpointOperationV1",
        ),
        (
            "endpoint-operation-diagnostic-result-v1.json",
            "endpoint-operation-diagnostic-result-v1.json",
            "EndpointDiagnosticResultV1",
        ),
    ],
)
def test_committed_schema_and_golden_fixture_match_contract(
    schema_name: str, fixture_name: str, model_name: str
) -> None:
    contracts = _contracts()
    fixture = _fixture(fixture_name)
    model = getattr(contracts, model_name)

    assert model.model_validate(deepcopy(fixture)).model_dump(
        mode="json", exclude_none=True
    ) == fixture
    _schema_validator(schema_name).validate(fixture)


def test_create_schema_rejects_url_like_reason_and_execution_extensions() -> None:
    _contracts()
    validator = _schema_validator("endpoint-operation-create-v1.json")

    for invalid_request in (
        {**_create_request(), "parameters": {"reason": "https://bad"}},
        {**_create_request(), "ticket_id": "ticket-1"},
        {**_create_request(), "executable": "powershell.exe"},
        {**_create_request(), "parameters": {"reason": "ok", "target_url": "x"}},
    ):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid_request)


def test_invalid_golden_fixture_is_rejected_by_model_and_schema() -> None:
    contracts = _contracts()
    fixture = _fixture("invalid/endpoint-operation-create-url-reason-v1.json")

    with pytest.raises(ValidationError):
        contracts.EndpointOperationCreateV1.model_validate(fixture)
    with pytest.raises(JsonSchemaValidationError):
        _schema_validator("endpoint-operation-create-v1.json").validate(fixture)
