"""Service and printer DTOs exclude execution and print-document data."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError


def test_service_key_is_fixed_and_cannot_be_an_scm_name() -> None:
    from endpoint_contracts.service_printer_primitives import ServiceStatusParametersV1

    with pytest.raises(ValidationError):
        ServiceStatusParametersV1(schema_version="service_status_v2_parameters_v1", service_key="arbitrary-service")
    with pytest.raises(ValidationError):
        ServiceStatusParametersV1(schema_version="service_status_v2_parameters_v1", service_key="print_service", action="restart")


def test_printer_result_rejects_job_document_and_owner() -> None:
    from endpoint_contracts.service_printer_primitives import PrinterQueueSummaryResultV1

    payload = dict(
        schema_version="printer_queue_summary_result_v1",
        job_count=1,
        printing_count=0,
        queued_count=1,
        paused_count=0,
        error_count=0,
        oldest_job_age_seconds=30,
        status="succeeded",
        collected_at=datetime.now(UTC),
    )
    assert PrinterQueueSummaryResultV1.model_validate(payload).job_count == 1
    with pytest.raises(ValidationError):
        PrinterQueueSummaryResultV1.model_validate({**payload, "document_name": "private.docx"})
    with pytest.raises(ValidationError):
        PrinterQueueSummaryResultV1.model_validate({**payload, "username": "operator"})


def test_printer_identifier_rejects_control_characters() -> None:
    from endpoint_contracts.service_printer_primitives import PrinterStatusParametersV1

    with pytest.raises(ValidationError):
        PrinterStatusParametersV1(schema_version="printer_status_parameters_v1", printer_name="Office\nPrinter")


def test_service_and_printer_descriptors_use_fixed_policies() -> None:
    from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY

    for capability in ("service.list", "service.status"):
        assert MODULE_CAPABILITY_REGISTRY[capability].metadata.policy == "service_catalog"
    for capability in ("printer.list", "printer.status", "printer.queue.summary"):
        assert MODULE_CAPABILITY_REGISTRY[capability].metadata.policy == "local_printers"
