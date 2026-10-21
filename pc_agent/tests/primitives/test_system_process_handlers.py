"""Bounded System/Process primitives, native smoke check and privacy boundary."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

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


@pytest.fixture
def bounded_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    from pc_agent.primitives.system_process import handlers

    processes = [SimpleNamespace(info={
        "pid": 123,
        "name": "privacy-fixture.exe",
        "status": "running",
        "cpu_percent": 0.0,
        "memory_info": SimpleNamespace(rss=4096),
        "cmdline": "private-command-must-not-be-returned",
    })]
    monkeypatch.setattr(handlers.psutil, "process_iter", lambda **kwargs: iter(processes))


def test_native_process_list_reports_safe_fields() -> None:
    from pc_agent.primitives.system_process.handlers import process_list

    result = process_list(ProcessListParametersV1(schema_version="process_list_parameters_v1"))
    assert result.status == "succeeded"
    assert 0 < result.process_count <= 32
    assert all(set(item.model_dump()) == {"pid", "name", "state", "cpu_percent", "memory_bytes"} for item in result.processes)


def test_process_list_and_find_expose_only_safe_fields(bounded_processes: None) -> None:
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


def test_process_find_uses_plain_text_for_regex_metacharacters(bounded_processes: None) -> None:
    from pc_agent.primitives.system_process.handlers import process_find

    result = process_find(ProcessFindParametersV1(schema_version="process_find_parameters_v1", name=".*"))
    assert result.status == "succeeded"
    assert not result.present


def test_process_find_reports_failure_when_enumeration_exceeds_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    from pc_agent.primitives.system_process import handlers

    clock = iter([0.0, handlers._PROCESS_DEADLINE_SECONDS])
    monkeypatch.setattr(handlers.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(handlers.psutil, "process_iter", lambda **kwargs: iter([SimpleNamespace(info={})]))

    result = handlers.process_find(ProcessFindParametersV1(
        schema_version="process_find_parameters_v1", name="deadline-fixture.exe",
    ))

    assert result.status == "failed"
    assert result.error_code == "process_find_failed"
    assert not result.present
    assert result.matches == []
