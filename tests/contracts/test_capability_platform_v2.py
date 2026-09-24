"""Closed DTO boundaries for Capability Platform v2."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError


def test_system_and_process_dtos_reject_unapproved_fields() -> None:
    from endpoint_contracts.system_process_primitives import (
        ProcessFindParametersV1,
        ProcessListParametersV1,
        ProcessSummaryV1,
        SystemResourceSnapshotParametersV1,
    )

    for model, payload in (
        (SystemResourceSnapshotParametersV1, {"schema_version": "system_resource_snapshot_parameters_v1", "path": "C:\\"}),
        (ProcessListParametersV1, {"schema_version": "process_list_parameters_v1", "command": "whoami"}),
        (ProcessFindParametersV1, {"schema_version": "process_find_parameters_v1", "name": "agent", "regex": True}),
        (ProcessFindParametersV1, {"schema_version": "process_find_parameters_v1", "name": "x" * 129}),
        (ProcessSummaryV1, {"pid": 1, "name": "x", "state": "running", "cpu_percent": 0.0, "memory_bytes": 10, "cmdline": ["secret"]}),
    ):
        with pytest.raises(ValidationError):
            model.model_validate(payload)


def test_process_results_are_bounded_and_disallow_private_fields() -> None:
    from endpoint_contracts.system_process_primitives import (
        ProcessListResultV1,
        ProcessSummaryV1,
    )

    item = ProcessSummaryV1(pid=1, name="agent", state="running", cpu_percent=0.0, memory_bytes=1024)
    with pytest.raises(ValidationError):
        ProcessListResultV1(
            schema_version="process_list_result_v1",
            processes=[item] * 33,
            process_count=33,
            status="succeeded",
            collected_at=datetime.now(UTC),
        )


def test_catalog_describes_system_and_process_capabilities() -> None:
    from endpoint_contracts.capabilities import module_capability_catalog

    items = {item.capability: item for item in module_capability_catalog().items}
    for capability, category, risk in (
        ("system.resource_snapshot", "system", "safe_read"),
        ("process.list", "process", "controlled_read"),
        ("process.find", "process", "safe_read"),
    ):
        item = items[capability]
        assert item.category == category
        assert item.risk == risk
        assert item.display_name_ru
        assert item.minimum_agent_version >= "3.2.67"
        assert item.platforms == ["linux_amd64", "windows_amd64"]
