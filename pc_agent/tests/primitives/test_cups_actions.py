from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from endpoint_contracts import AgentCommandV1
from endpoint_contracts.cups_actions import CUPS_QUEUE_CONFIGURE, CUPS_TEST_PAGE_SUBMIT
from endpoint_contracts.gateway_ws import GatewayCommandV1
from pc_agent.primitives.service_printer import cups_actions
from pc_agent.runtime.command_executor import CommandExecutor


def _command(capability, parameters, *, key="cups-action-test"):
    now = datetime.now(UTC)
    return {
        "schema_version": "agent_command_v1", "command_id": uuid4(), "device_id": uuid4(),
        "capability": capability, "parameters": parameters, "requested_by_service": "endpoint-platform",
        "idempotency_key": key, "created_at": now, "deadline_at": now + timedelta(minutes=1),
    }


@pytest.mark.parametrize("parameters", [
    {"queue": "-x"},
    {"queue": "other/printer"},
    {"queue": "all"},
    {"queue": "office", "copies": 2},
    {"queue": "office", "file": "/tmp/private"},
])
def test_test_page_gateway_contract_limits_destination_and_document(parameters):
    with pytest.raises(ValidationError):
        GatewayCommandV1.model_validate(_command(CUPS_TEST_PAGE_SUBMIT, parameters))


def test_configure_requires_an_explicit_change():
    with pytest.raises(ValidationError):
        AgentCommandV1.model_validate(_command(CUPS_QUEUE_CONFIGURE, {"queue": "office"}))


@pytest.mark.asyncio
async def test_configure_sets_queue_state_in_place_and_replays_journal(tmp_path, monkeypatch):
    enabled = accepting = False
    calls = []

    def cups(program, *args):
        nonlocal enabled, accepting
        calls.append((program, *args))
        assert args[-1] == "office"
        if program == "lpstat":
            if args[0] == "-p":
                return "printer office is idle. enabled since now" if enabled else "printer office disabled since now"
            return "office accepting requests since now" if accepting else "office not accepting requests since now"
        if program == "cupsenable":
            enabled = True
        elif program == "cupsaccept":
            accepting = True
        else:
            pytest.fail(f"unexpected CUPS invocation: {program}")
        assert args == ("office",)
        return ""

    monkeypatch.setattr(cups_actions, "_run_cups", cups)
    command = GatewayCommandV1.model_validate(_command(CUPS_QUEUE_CONFIGURE, {
        "queue": "office", "enabled": "on", "accepting": "on",
    }))
    journal = tmp_path / "cups-actions.sqlite3"
    monkeypatch.setattr(cups_actions.sys, "platform", "linux")
    executor = CommandExecutor(cups_journal=journal)
    first = await executor.execute(command)
    assert first.status == "succeeded"
    result = first.result_items[0]
    assert result["before"] == {"enabled": False, "accepting": False}
    assert result["after"] == {"enabled": True, "accepting": True}
    assert [call[0] for call in calls].count("cupsenable") == 1
    assert [call[0] for call in calls].count("cupsaccept") == 1
    count = len(calls)
    assert await CommandExecutor(cups_journal=journal).execute(command) == first
    assert len(calls) == count


@pytest.mark.asyncio
@pytest.mark.parametrize("lost_ack", [False, True])
async def test_test_page_submission_runs_at_most_once_across_new_executor(tmp_path, monkeypatch, lost_ack):
    submissions = []

    def cups(program, *args):
        if program == "lpstat":
            return "printer office is idle. enabled since now" if args[0] == "-p" else "office accepting requests since now"
        assert program == "lp"
        submissions.append(args)
        assert args[:4] == ("-d", "office", "-n", "1")
        assert "job-sheets=none" in args
        assert args[args.index("-P") + 1] == "1"
        assert args[-2] == "--"
        with open(args[-1], encoding="ascii") as page:
            assert page.read().startswith("Endpoint Platform")
        if lost_ack:
            raise TimeoutError
        return "request id is office-42 (1 file(s))"

    monkeypatch.setattr(cups_actions, "_run_cups", cups)
    monkeypatch.setattr(cups_actions.sys, "platform", "linux")
    command = AgentCommandV1.model_validate(_command(CUPS_TEST_PAGE_SUBMIT, {"queue": "office"}))
    journal = tmp_path / "cups-actions.sqlite3"
    first = await CommandExecutor(cups_journal=journal).execute(command)
    replay = await CommandExecutor(cups_journal=journal).execute(command)
    assert replay == first and len(submissions) == 1
    assert first.result_items[0]["outcome"] == ("unknown" if lost_ack else "submitted")
    assert first.result_items[0]["job_id"] == (None if lost_ack else "office-42")
