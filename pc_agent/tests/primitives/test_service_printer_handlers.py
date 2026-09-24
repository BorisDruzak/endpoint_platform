"""Fixed service keys and privacy-preserving printer reads."""

from __future__ import annotations

from endpoint_contracts.service_printer_primitives import (
    PrinterListParametersV1,
    PrinterQueueSummaryParametersV1,
    PrinterStatusParametersV1,
    ServiceListParametersV1,
    ServiceStatusParametersV1,
)


def test_fixed_service_catalog_maps_print_service_per_platform() -> None:
    from pc_agent.primitives.service_printer.handlers import service_list, service_status

    seen: list[str] = []
    def query(name: str) -> tuple[bool, str, str]:
        seen.append(name)
        return (True, "running", "automatic")

    result = service_status(
        ServiceStatusParametersV1(schema_version="service_status_v2_parameters_v1", service_key="print_service"),
        platform_name="windows",
        windows_query=query,
    )
    assert result.service.state == "running"
    assert seen == ["Spooler"]
    listed = service_list(
        ServiceListParametersV1(schema_version="service_list_parameters_v1"),
        platform_name="linux",
        linux_query=query,
    )
    assert len(listed.services) == 3
    assert "endpoint-agent-update.service" in seen
    assert "cups.service" in seen


def test_no_printers_is_safe_empty_result_and_unknown_name_is_absent() -> None:
    from pc_agent.primitives.service_printer.handlers import printer_list, printer_status

    listed = printer_list(
        PrinterListParametersV1(schema_version="printer_list_parameters_v1"),
        enumerate_printers=lambda: [],
    )
    assert listed.status == "succeeded"
    assert listed.printers == []
    status = printer_status(
        PrinterStatusParametersV1(schema_version="printer_status_parameters_v1", printer_name="Office"),
        enumerate_printers=lambda: [],
    )
    assert status.status == "succeeded"
    assert not status.exists


def test_cups_no_destinations_is_an_empty_inventory(monkeypatch) -> None:
    from pc_agent.primitives.service_printer import handlers

    monkeypatch.setattr(handlers, "_execute_bounded_command", lambda command, timeout, limit: b"lpstat: No destinations added.")
    assert handlers._linux_printers() == []


def test_queue_summary_discards_private_backend_fields() -> None:
    from pc_agent.primitives.service_printer.handlers import printer_queue_summary

    result = printer_queue_summary(
        PrinterQueueSummaryParametersV1(schema_version="printer_queue_summary_parameters_v1"),
        query_summary=lambda: {"job_count": 1, "printing_count": 0, "queued_count": 1, "paused_count": 0, "error_count": 0, "oldest_job_age_seconds": 12, "document_name": "secret.docx", "username": "person"},
    )
    assert result.status == "succeeded"
    assert result.job_count == 1
    assert "secret" not in str(result.model_dump(mode="json"))
    assert "person" not in str(result.model_dump(mode="json"))
