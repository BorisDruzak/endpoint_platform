"""Minimal TLS-only Endpoint Platform Gateway poller for the ALT service."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import aiohttp

from endpoint_contracts import (
    AgentCommandAckV1,
    AgentHelloV1,
    AgentResultV1,
)
from pc_agent.context_profiles.command_execution import execute_context_agent_command
from pc_agent.context_profiles.probe import SystemProbe
from pc_agent.device_credential import read_device_credential
from pc_agent.enrollment_bootstrap import PERMANENT_CREDENTIAL_PATH
from pc_agent.gateway_update_runtime import GatewayUpdateRuntime
from pc_agent.transport.http_pull import (
    DEFAULT_ENDPOINT_ORIGIN,
    GatewayCredentialRejected,
    GatewayNoCommandAvailable,
    HttpPullGatewayTransport,
    require_gateway_response,
    validate_endpoint_origin,
)
from pc_agent.update_adapter import EndpointRecommendation, EndpointUpdateAdapter
from pc_agent.version import EXIT_UPDATE_PENDING

_ORIGIN = DEFAULT_ENDPOINT_ORIGIN
_ALT_CURRENT_SELECTOR = Path("/opt/endpoint-agent/current.json")
GATEWAY_UPDATE_POLL_INTERVAL_SEC = 300.0


@dataclass(frozen=True, slots=True)
class GatewayAttemptOutcome:
    """A successful single poll and the delay before the next lifecycle attempt."""

    delay_before_next: float


def _credential() -> str:
    return read_device_credential(PERMANENT_CREDENTIAL_PATH)


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


def _endpoint_origin(origin: str | None = None) -> tuple[str, str]:
    """Return the only permitted HTTPS controller origin components."""
    return validate_endpoint_origin(_ORIGIN if origin is None else origin)


async def _download_gateway_artifact(
    session: aiohttp.ClientSession,
    item: EndpointRecommendation,
    destination: Path,
    *,
    endpoint_origin: str | None = None,
    credential_source=None,
) -> tuple[str, int]:
    """Stream a controller-hosted artifact through the existing pinned TLS session."""
    origin_scheme, origin_netloc = _endpoint_origin(endpoint_origin)
    load_credential = credential_source or _credential
    parsed = urlsplit(item.artifact_url)
    if (parsed.scheme, parsed.netloc) != (origin_scheme, origin_netloc):
        raise ValueError("Gateway update artifact must use the Endpoint origin")
    temporary = destination.with_name(f".{destination.name}.tmp")
    digest = hashlib.sha256()
    size = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        async with session.get(
            item.artifact_url,
            headers={"Authorization": f"Bearer {load_credential()}"},
            allow_redirects=False,
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


def _gateway_update_runtime(
    session: aiohttp.ClientSession,
    *,
    endpoint_origin: str | None = None,
    credential_source=None,
    data_root: Path | None = None,
    current_selector: Path | None = None,
) -> GatewayUpdateRuntime:
    configured_origin = _ORIGIN if endpoint_origin is None else endpoint_origin
    load_credential = credential_source or _credential
    runtime_data_root = data_root or PERMANENT_CREDENTIAL_PATH.parent
    adapter = EndpointUpdateAdapter(
        api_url=configured_origin,
        bearer_token=load_credential,
        session=session,
        data_root=runtime_data_root,
    )
    return GatewayUpdateRuntime(
        adapter=adapter,
        data_root=runtime_data_root,
        current_version=read_gateway_current_version(
            current_selector or _ALT_CURRENT_SELECTOR
        ),
        download=lambda item, destination: _download_gateway_artifact(
            session,
            item,
            destination,
            endpoint_origin=configured_origin,
            credential_source=load_credential,
        ),
    )


async def run_gateway_once(
    *,
    ca_file: Path,
    command_executor: object | None = None,
    credential: str | None = None,
    endpoint_origin: str | None = None,
    data_root: Path | None = None,
    current_selector: Path | None = None,
    poll_updates: bool = True,
    on_update_poll_complete: Callable[[], None] | None = None,
) -> GatewayAttemptOutcome:
    """Compatibility entrypoint implemented through the HTTP-pull transport."""
    use_default_update_runtime = (
        credential is None
        and endpoint_origin is None
        and data_root is None
        and current_selector is None
    )
    configured_origin = _ORIGIN if endpoint_origin is None else endpoint_origin
    _endpoint_origin(configured_origin)
    credential_source = _credential if credential is None else lambda: credential
    token = credential_source()
    async def on_connected(session: aiohttp.ClientSession) -> None:
        if use_default_update_runtime:
            update_runtime = _gateway_update_runtime(session)
        else:
            update_runtime = _gateway_update_runtime(
                session,
                endpoint_origin=configured_origin,
                credential_source=credential_source,
                data_root=data_root,
                current_selector=current_selector,
            )
        await update_runtime.report_startup_outcome()
        if poll_updates:
            update_result = await update_runtime.run_once()
            if on_update_poll_complete is not None:
                on_update_poll_complete()
            if update_result.status == "scheduled":
                raise SystemExit(EXIT_UPDATE_PENDING)

    transport = HttpPullGatewayTransport(
        ca_file=ca_file,
        credential=token,
        endpoint_origin=configured_origin,
        on_connected=on_connected,
    )
    try:
        await transport.connect(_http_pull_compatibility_hello())
        try:
            inbound = await transport.receive()
        except GatewayNoCommandAvailable:
            return GatewayAttemptOutcome(delay_before_next=5.0)
        if inbound.root.kind != "command":
            raise ValueError("HTTP pull returned a non-command inbound message")
        command = inbound.root.payload
        ack = AgentCommandAckV1(
            schema_version="agent_command_ack_v1",
            command_id=command.command_id,
            device_id=command.device_id,
            status="acknowledged",
            acknowledged_at=datetime.now(UTC),
        )
        await transport.send_ack(ack)
        if command_executor is None:
            result = execute_context_agent_command(command, probe=SystemProbe())
        else:
            result = await command_executor.execute(command)
        await transport.send_result(result)
        return GatewayAttemptOutcome(delay_before_next=0.0)
    finally:
        await transport.close()


def _http_pull_compatibility_hello() -> AgentHelloV1:
    """Supply the local-only contract value required by a non-handshaking pull."""
    return AgentHelloV1(
        schema_version="agent_hello_v1",
        device_id=UUID(int=0),
        agent_instance_id=UUID(int=0),
        agent_version="http-pull",
        launcher_version="http-pull",
        platform="linux_amd64",
        boot_id="http-pull",
        capabilities=[
            "context.baseline.collect",
            "context.diagnostic.collect",
            "context.health.collect",
            "context.network.collect",
        ],
        last_result_sequence=0,
        last_policy_revision=0,
    )
