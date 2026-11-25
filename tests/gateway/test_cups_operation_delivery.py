from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from endpoint_contracts.cups_actions import CUPS_TEST_PAGE_SUBMIT
from endpoint_contracts import AgentCommandAckV1
from endpoint_server.auth import scopes as auth
from endpoint_server.db.models import AuditEvent, ServiceClient, ServiceCredential
from endpoint_server.gateway.command_service import CommandService, next_pending_command
from endpoint_server.main import create_app
from pc_agent.primitives.service_printer import cups_actions
from pc_agent.runtime.command_executor import CommandExecutor

from .conftest import gateway_settings, seed_device
from .test_endpoint_operation_delivery import _open_session


@pytest.mark.asyncio
async def test_separate_cups_scope_delivers_once_and_records_outcome(session_provider, tmp_path, monkeypatch):
    settings = replace(gateway_settings(artifact_root=tmp_path), endpoint_operations_api_enabled=True)
    device_id = (await seed_device(session_provider)).id
    async with session_provider() as session:
        client = ServiceClient(id=uuid4(), client_identifier="cups-operator-fixture", display_name="CUPS operator")
        session.add(client)
        await session.commit()
    principals = {
        "print": auth.ServicePrincipal(client, ServiceCredential(scopes=["cups.test_page.submit", "cups.operations.read", "operations.read"])),
        "read": auth.ServicePrincipal(client, ServiceCredential(scopes=["operations.read"])),
        "foreign": auth.ServicePrincipal(ServiceClient(id=uuid4()), ServiceCredential(scopes=["cups.operations.read"])),
    }

    async def load_principal(_session, token, _pepper):
        return principals.get(token)

    monkeypatch.setattr(auth, "_load_service_principal", load_principal)

    submitted = []

    def run_cups(program, *arguments):
        if program == "lpstat":
            return "printer office disabled since now" if arguments[0] == "-p" else "office accepting requests since now"
        assert program == "lp"
        submitted.append(arguments)
        return "request id is office-42 (1 file(s))"

    monkeypatch.setattr(cups_actions, "_run_cups", run_cups)
    monkeypatch.setattr(cups_actions.sys, "platform", "linux")
    app = create_app(settings, session_provider)
    base = f"/api/v1/devices/{device_id}/cups"
    headers = {"Authorization": "Bearer print", "Idempotency-Key": str(uuid4()), "X-Correlation-ID": "cups-fixture"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://endpoint") as http:
        denied = await http.post(f"{base}/queue-configurations", headers=headers, json={"queue": "office", "enabled": "on"})
        assert denied.status_code == 403
        denied = await http.post(f"{base}/test-pages", json={"queue": "office"},
                                 headers={**headers, "Authorization": "Bearer read"})
        assert denied.status_code == 403
        response = await http.post(f"{base}/test-pages", json={"queue": "office"}, headers=headers)
        assert response.status_code == 201, response.text
        operation_id = response.json()["data"]["operation_id"]
        async with session_provider() as session:
            assert await next_pending_command(session, device_id, transport="http_pull") is None

        agent_instance = uuid4()
        presence = await _open_session(
            session_provider, device_id=device_id, instance_id=agent_instance, capabilities=[CUPS_TEST_PAGE_SUBMIT],
        )
        service = CommandService(session_provider)
        sent = []
        assert await service.scheduled_pending_devices({device_id: {CUPS_TEST_PAGE_SUBMIT}}) == (device_id,)
        for capabilities, platform in ((set(), "linux_amd64"), ({CUPS_TEST_PAGE_SUBMIT}, "windows_amd64")):
            assert not await service.deliver_next(
                device_id, presence.session_id, sent.append, allowed_capabilities=capabilities, agent_platform=platform
            )
        assert sent == []
        assert await service.deliver_next(device_id, presence.session_id, sent.append,
                                          allowed_capabilities={CUPS_TEST_PAGE_SUBMIT}, agent_platform="linux_amd64")
        await service.record_ack(device_id=device_id, session_id=presence.session_id, acknowledgement=AgentCommandAckV1(
            schema_version="agent_command_ack_v1", command_id=sent[0].payload.command_id, device_id=device_id,
            status="acknowledged", acknowledged_at=datetime.now(UTC),
        ))
        result = await CommandExecutor(cups_journal=tmp_path / "cups.sqlite3").execute(sent[0].payload)
        other_install = await _open_session(session_provider, device_id=device_id, capabilities=[CUPS_TEST_PAGE_SUBMIT])
        assert not await service.deliver_next(device_id, other_install.session_id, sent.append,
                                              allowed_capabilities={CUPS_TEST_PAGE_SUBMIT}, agent_platform="linux_amd64")
        presence = await _open_session(
            session_provider, device_id=device_id, instance_id=agent_instance, capabilities=[CUPS_TEST_PAGE_SUBMIT],
        )
        assert await service.deliver_next(device_id, presence.session_id, sent.append,
                                          allowed_capabilities={CUPS_TEST_PAGE_SUBMIT}, agent_platform="linux_amd64")
        assert sent[0].payload == sent[1].payload
        assert await CommandExecutor(cups_journal=tmp_path / "cups.sqlite3").execute(sent[1].payload) == result
        for _ in range(2):
            await service.record_result(device_id=device_id, device_instance_id=presence.device_instance_id,
                                        session_id=presence.session_id, result_sequence=1, result=result)
        read = await http.get(f"/api/v1/cups-operations/{operation_id}", headers=headers)
        assert read.status_code == 200, read.text
        assert read.json()["data"]["result"]["job_id"] == "office-42"
        assert read.json()["data"]["status"] == "succeeded"
        assert (await http.get(f"/api/v1/cups-operations/{operation_id}",
                               headers={**headers, "Authorization": "Bearer foreign"})).status_code == 404
        replay = await http.post(f"{base}/test-pages", json={"queue": "office"}, headers=headers)
        assert replay.status_code == 200 and replay.json() == read.json()
        changed = await http.post(f"{base}/test-pages", json={"queue": "different"}, headers=headers)
        assert changed.status_code == 409
        assert (await http.get(f"/api/v1/operations/{operation_id}", headers=headers)).status_code == 404

    assert len(submitted) == 1
    async with session_provider() as session:
        audit = (await session.scalars(select(AuditEvent).where(AuditEvent.object_identifier == operation_id)
                                       .order_by(AuditEvent.created_at))).all()
        assert [entry.action for entry in audit] == ["endpoint.cups_action_queued", "endpoint.cups_action_succeeded"]
        assert audit[0].actor_identifier == "cups-operator-fixture"
        assert audit[1].details["cups_job_id"] == "office-42"
