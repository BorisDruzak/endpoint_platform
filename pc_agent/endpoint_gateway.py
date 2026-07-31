"""Minimal TLS-only Endpoint Platform Gateway poller for the ALT service."""

from __future__ import annotations

import asyncio
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path

import aiohttp

from endpoint_contracts import AgentCommandAckV1, AgentCommandV1, AgentResultV1
from pc_agent.context_profiles.probe import SystemProbe
from pc_agent.core.orchestrator import execute_context_agent_command
from pc_agent.enrollment_bootstrap import PERMANENT_CREDENTIAL_PATH

_ORIGIN = "https://endpoint.sosnadmin.local"


class GatewayCredentialRejected(RuntimeError):
    """The controller rejected a durable credential; do not retry it in-process."""


def require_gateway_response(response: aiohttp.ClientResponse) -> None:
    if response.status in {401, 403}:
        raise GatewayCredentialRejected("Endpoint Gateway rejected device credential")
    response.raise_for_status()


def _credential() -> str:
    value = PERMANENT_CREDENTIAL_PATH.read_text(encoding="ascii").strip()
    if len(value) != 43 or any(ch.isspace() for ch in value):
        raise ValueError("invalid Endpoint device credential")
    return value


async def run_gateway_forever(*, ca_file: Path) -> None:
    """Poll only the fixed HTTPS Gateway; transient outages never stop the service."""
    context = ssl.create_default_context(cafile=str(ca_file))
    while True:
        try:
            token = _credential()
            headers = {"Authorization": f"Bearer {token}"}
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
                async with session.get(f"{_ORIGIN}/agent/v1/gateway/commands/next", headers=headers, ssl=context) as response:
                    if response.status == 204:
                        await asyncio.sleep(5)
                        continue
                    require_gateway_response(response)
                    command = AgentCommandV1.model_validate(await response.json())
                ack = AgentCommandAckV1(schema_version="agent_command_ack_v1", command_id=command.command_id, device_id=command.device_id, status="acknowledged", acknowledged_at=datetime.now(UTC))
                async with session.post(f"{_ORIGIN}/agent/v1/gateway/commands/{command.command_id}/ack", headers=headers, json=ack.model_dump(mode="json"), ssl=context) as response:
                    require_gateway_response(response)
                result = execute_context_agent_command(command, probe=SystemProbe())
                async with session.post(f"{_ORIGIN}/agent/v1/gateway/commands/{command.command_id}/results", headers=headers, json=result.model_dump(mode="json"), ssl=context) as response:
                    require_gateway_response(response)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError, json.JSONDecodeError):
            await asyncio.sleep(5)
