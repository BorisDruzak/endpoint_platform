"""Real bounded System/Process primitives and privacy boundary."""

from __future__ import annotations

from endpoint_contracts.system_process_primitives import (
    ProcessFindParametersV1,
    ProcessListParametersV1,
    SystemResourceSnapshotParametersV1,
)


def test_system_snapshot_reports_machine_facts_without_process_data() -> None:
    from pc_agent.primitives.system_process.handlers import resource_snapshot

    result = resource_snapshot(SystemResourceSnapshotParametersV1(schema_version="system_resource_snapshot_parameters_v1"))
    assert result.status == "succeeded"
    assert result.memory_total_bytes > 0
    assert 0 <= result.cpu_percent <= 100
    assert "processes" not in result.model_dump()


def test_process_list_and_find_expose_only_safe_fields() -> None:
    from pc_agent.primitives.system_process.handlers import process_find, process_list

    listed = process_list(ProcessListParametersV1(schema_version="process_list_parameters_v1"))
    assert listed.status == "succeeded"
    assert 0 < listed.process_count <= 32
    assert all(set(item.model_dump()) == {"pid", "name", "state", "cpu_percent", "memory_bytes"} for item in listed.processes)
    target = listed.processes[0].name
    found = process_find(ProcessFindParametersV1(schema_version="process_find_parameters_v1", name=target))
    assert found.status == "succeeded"
    assert found.present
    assert found.process_count >= 1
    assert all(item.name.casefold() == target.casefold() for item in found.matches)


def test_process_find_uses_plain_text_for_regex_metacharacters() -> None:
    from pc_agent.primitives.system_process.handlers import process_find

    result = process_find(ProcessFindParametersV1(schema_version="process_find_parameters_v1", name=".*"))
    assert result.status == "succeeded"
    assert not result.present
