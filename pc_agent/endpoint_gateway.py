"""Minimal TLS-only Endpoint Platform Gateway poller for the ALT service."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import ssl
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp

from endpoint_contracts import AgentCommandAckV1, AgentCommandV1, AgentResultV1
from pc_agent.context_profiles.probe import SystemProbe
from pc_agent.core.orchestrator import execute_context_agent_command
from pc_agent.enrollment_bootstrap import PERMANENT_CREDENTIAL_PATH
from pc_agent.gateway_update_runtime import GatewayUpdateRuntime
from pc_agent.update_adapter import EndpointRecommendation, EndpointUpdateAdapter
from pc_agent.version import EXIT_UPDATE_PENDING

_ORIGIN = "https://endpoint.sosnadmin.local"
_ALT_CURRENT_SELECTOR = Path("/opt/endpoint-agent/current.json")
_UPDATE_POLL_INTERVAL_SEC = 300.0


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


def read_gateway_current_version(selector_path: Path = _ALT_CURRENT_SELECTOR) -> str:
    """Read the immutable ALT selector instead of a legacy runtime setting."""
    try:
        selector = json.loads(Path(selector_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid ALT release selector") from exc
    if (
        not isinstance(selector, dict)
        or set(selector) != {"schema_version", "source_revision", "version"}
        or selector.get("schema_version") != 1
        or not isinstance(selector.get("source_revision"), str)
        or not isinstance(selector.get("version"), str)
    ):
        raise ValueError("invalid ALT release selector")
    return selector["version"]


async def _download_gateway_artifact(
    session: aiohttp.ClientSession,
    item: EndpointRecommendation,
    destination: Path,
) -> tuple[str, int]:
    """Stream a controller-hosted artifact through the existing pinned TLS session."""
    parsed = urlsplit(item.artifact_url)
    if parsed.scheme != "https" or parsed.netloc != urlsplit(_ORIGIN).netloc:
        raise ValueError("Gateway update artifact must use the Endpoint origin")
    temporary = destination.with_name(f".{destination.name}.tmp")
    digest = hashlib.sha256()
    size = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        async with session.get(
            item.artifact_url, headers={"Authorization": f"Bearer {_credential()}"}
        ) as response:
            require_gateway_response(response)
            if response.status != 200:
                raise ValueError("Gateway update artifact is unavailable")
            with temporary.open("wb") as output:
                async for chunk in response.content.iter_chunked(1024 * 1024):
                    size += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
        actual = digest.hexdigest()
        if actual != item.sha256 or size != item.size:
            raise ValueError("Gateway update artifact integrity mismatch")
        os.chmod(temporary, 0o600)
        temporary.replace(destination)
        return actual, size
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _gateway_update_runtime(session: aiohttp.ClientSession) -> GatewayUpdateRuntime:
    data_root = PERMANENT_CREDENTIAL_PATH.parent
    adapter = EndpointUpdateAdapter(
        api_url=_ORIGIN,
        bearer_token=_credential,
        session=session,
        data_root=data_root,
    )
    return GatewayUpdateRuntime(
        adapter=adapter,
        data_root=data_root,
        current_version=read_gateway_current_version(),
        download=lambda item, destination: _download_gateway_artifact(
            session, item, destination
        ),
    )


async def run_gateway_forever(*, ca_file: Path) -> None:
    """Poll only the fixed HTTPS Gateway; transient outages never stop the service."""
    context = ssl.create_default_context(cafile=str(ca_file))
    next_update_poll_at = 0.0
    while True:
        try:
            token = _credential()
            headers = {"Authorization": f"Bearer {token}"}
            connector = aiohttp.TCPConnector(ssl=context)
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20), connector=connector
            ) as session:
                update_runtime = _gateway_update_runtime(session)
                await update_runtime.report_startup_outcome()
                now = asyncio.get_running_loop().time()
                if now >= next_update_poll_at:
                    update_result = await update_runtime.run_once()
                    next_update_poll_at = now + _UPDATE_POLL_INTERVAL_SEC
                    if update_result.status == "scheduled":
                        raise SystemExit(EXIT_UPDATE_PENDING)
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
