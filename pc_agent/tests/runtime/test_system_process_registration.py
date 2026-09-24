"""System and Process capabilities use the existing Gateway runtime path."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from endpoint_contracts.commands import AgentCommandV1
from pc_agent.runtime.command_executor import CommandExecutor
from pc_agent.transport.protocol import compatibility_agent_hello


def _command(capability: str, parameters: dict[str, object]) -> AgentCommandV1:
    now = datetime.now(UTC)
    return AgentCommandV1(
        schema_version="agent_command_v1",
        command_id=uuid4(),
        device_id=uuid4(),
        capability=capability,
        parameters=parameters,
        requested_by_service="endpoint-platform",
        idempotency_key=f"system-process-{uuid4()}",
        created_at=now,
        deadline_at=now + timedelta(seconds=30),
    )


def test_new_capabilities_are_advertised_and_executable() -> None:
    assert {"system.resource_snapshot", "process.list", "process.find"} <= set(compatibility_agent_hello().capabilities)

    async def run() -> None:
        executor = CommandExecutor()
        await executor.start()
        try:
            for capability, parameters, discriminator in (
                ("system.resource_snapshot", {}, "system_resource_snapshot_result_v1"),
                ("process.list", {}, "process_list_result_v1"),
                ("process.find", {"name": "nonexistent-process-123"}, "process_find_result_v1"),
            ):
                result = await executor.execute(_command(capability, parameters))
                assert result.status == "succeeded"
                assert result.result_items[0]["schema_version"] == discriminator
        finally:
            await executor.stop()

    asyncio.run(run())


def test_agent_hello_advertises_only_implemented_platform_capabilities() -> None:
    linux = set(compatibility_agent_hello(platform="linux_amd64").capabilities)
    windows = set(compatibility_agent_hello(platform="windows_amd64").capabilities)
    assert "eventlog.query" not in linux
    assert "printer.queue.summary" not in linux
    assert {"eventlog.query", "printer.queue.summary"} <= windows
