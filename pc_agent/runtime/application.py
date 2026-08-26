"""Composition root for the neutral headless Endpoint Agent."""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import aiohttp

from pc_agent import endpoint_gateway
from pc_agent.device_credential import DeviceCredentialError, read_device_credential
from pc_agent.enrollment_identity import (
    ENROLLMENT_IDENTITY_FILENAME,
    read_enrollment_device_id,
)
from pc_agent.primitives.network.policy import AgentNetworkProbePolicy
from pc_agent.transport.base import GatewayTerminalError, GatewayTransport
from pc_agent.transport.http_pull import ClassifiedGatewayTransport
from pc_agent.transport.protocol import (
    AgentHelloV1,
    compatibility_agent_hello,
)
from pc_agent.transport.websocket import (
    MigrationFallbackGatewayTransport,
    WebSocketGatewayTransport,
)
from pc_agent.version import AGENT_VERSION

from .command_executor import CommandExecutor
from .lifecycle import (
    CredentialRejected,
    RuntimeDependencies,
    RuntimeExecutor,
    RuntimeLifecycle,
)
from .status import RuntimeStatus


_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    data_root: Path
    install_root: Path
    ca_file: Path
    endpoint_origin: str
    transport_mode: Literal["gateway_wss", "gateway_http_pull"]
    migration_http_pull_fallback: bool = False
    network_probe_allowed_cidrs: tuple[str, ...] = ()
    network_probe_allowed_suffixes: tuple[str, ...] = ()

    def validate(self) -> None:
        for name in ("data_root", "install_root", "ca_file"):
            if not isinstance(getattr(self, name), Path):
                raise ValueError(f"{name} must be a pathlib.Path")
        parsed = urlsplit(self.endpoint_origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Endpoint origin must be an absolute HTTPS origin")
        if self.transport_mode not in {"gateway_wss", "gateway_http_pull"}:
            raise ValueError("unsupported Endpoint transport mode")
        if not isinstance(self.migration_http_pull_fallback, bool):
            raise ValueError("migration HTTP pull fallback must be boolean")
        for name in (
            "network_probe_allowed_cidrs",
            "network_probe_allowed_suffixes",
        ):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not all(
                isinstance(value, str) for value in values
            ):
                raise ValueError(f"{name} must be a tuple of strings")
        self.network_probe_policy()
        if not self.ca_file.is_file():
            raise ValueError("Endpoint CA file is missing")

    def network_probe_policy(self) -> AgentNetworkProbePolicy:
        """Build the local fail-closed allowlist for typed network commands."""
        return AgentNetworkProbePolicy.from_values(
            allowed_cidrs=self.network_probe_allowed_cidrs,
            allowed_suffixes=self.network_probe_allowed_suffixes,
        )


class RuntimeApplication:
    def __init__(
        self,
        settings: RuntimeSettings,
        dependencies: RuntimeDependencies | None = None,
    ) -> None:
        self.settings = settings
        self.dependencies = dependencies or _default_dependencies(settings)
        self.status = RuntimeStatus()

    async def run(self) -> int:
        return await RuntimeLifecycle(
            self.settings, self.dependencies, self.status
        ).run()


async def run_runtime(settings: RuntimeSettings) -> int:
    try:
        settings.validate()
    except ValueError:
        return 1
    return await RuntimeApplication(settings).run()


def _default_dependencies(
    settings: RuntimeSettings | None = None,
) -> RuntimeDependencies:
    transport_state = _EndpointHttpPullState()

    def create_transport(
        settings: object, credential: str, executor: RuntimeExecutor
    ) -> GatewayTransport:
        return _create_transport(
            settings,
            credential,
            executor,
            state=transport_state,
        )

    def create_connected_tasks(
        settings: object, credential: str, transport: GatewayTransport
    ):
        if (
            isinstance(settings, RuntimeSettings)
            and settings.transport_mode == "gateway_wss"
            and isinstance(transport, WebSocketGatewayTransport)
        ):
            if os.name == "nt":
                return (_periodic_windows_update_checks(settings, credential),)
            return (
                _periodic_https_update_checks(
                    settings,
                    credential,
                    _EndpointHttpPullState(),
                ),
            )
        return ()

    create_executor = CommandExecutor
    if settings is not None:
        def create_configured_executor() -> CommandExecutor:
            return CommandExecutor(
                network_probe_policy=settings.network_probe_policy()
            )

        create_executor = create_configured_executor

    return RuntimeDependencies(
        load_credential=_load_credential,
        create_executor=create_executor,
        create_transport=create_transport,
        load_hello=_load_hello,
        after_server_handshake=_startup_proof_hook,
        create_connected_tasks=create_connected_tasks,
        create_completion_sink=_create_completion_sink,
        create_canary_status_writer=_create_canary_status_writer,
    )


def _create_canary_status_writer(settings: object):
    """Enable strict canary evidence only for the no-fallback Windows WSS runtime."""
    if (
        os.name != "nt"
        or not isinstance(settings, RuntimeSettings)
        or settings.transport_mode != "gateway_wss"
        or settings.migration_http_pull_fallback
    ):
        return None
    from pc_agent.platform.windows.canary_status import CanaryStatusWriter

    selector = settings.install_root / "current.json"
    try:
        details = selector.lstat()
        if selector.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
            raise ValueError("current selector is unsafe")
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("current selector is unsafe")
        payload = json.loads(selector.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "source_revision", "version"}
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("source_revision"), str)
        or not _SOURCE_REVISION.fullmatch(payload["source_revision"])
        or payload.get("version") != AGENT_VERSION
    ):
        return None
    return CanaryStatusWriter(
        settings.data_root,
        {"version": AGENT_VERSION, "source_revision": payload["source_revision"]},
        urlsplit(settings.endpoint_origin).hostname or "",
    )


def _create_completion_sink(settings: object):
    """Persist the bounded marker only for the Windows service runtime."""
    if os.name != "nt" or not isinstance(settings, RuntimeSettings):
        return None
    from pc_agent.platform.windows.completion_proof import WindowsCompletionProofWriter

    writer = WindowsCompletionProofWriter(settings.data_root)
    canary_status_writer = _create_canary_status_writer(settings)

    def append(marker: dict[str, object]) -> None:
        writer.append_marker(marker)
        if canary_status_writer is not None:
            canary_status_writer.with_completion(str(marker["command_id"]))

    return append


async def _startup_proof_hook(settings: object) -> None:
    """Only the connected agent, never the privileged updater, proves startup."""
    if not isinstance(settings, RuntimeSettings):
        return
    if os.name == "nt":
        from pc_agent.platform.windows.startup_confirmation import StartupProofWriter
        from pc_agent.platform.windows.update_paths import WindowsUpdatePaths

        StartupProofWriter(
            WindowsUpdatePaths(settings.install_root, settings.data_root / "updates" / "pending_update.json")
        ).record_after_server_handshake()


def _load_credential(settings: object) -> str:
    if not isinstance(settings, RuntimeSettings):
        raise CredentialRejected("invalid runtime settings")
    try:
        return read_device_credential(settings.data_root / "device-credential")
    except DeviceCredentialError as error:
        raise CredentialRejected(str(error)) from error


def _load_hello(settings: object) -> AgentHelloV1:
    if not isinstance(settings, RuntimeSettings):
        raise ValueError("invalid runtime settings")
    device_id = read_enrollment_device_id(
        settings.data_root / ENROLLMENT_IDENTITY_FILENAME
    )
    values: dict[str, object] = {"device_id": device_id}
    if settings.transport_mode == "gateway_wss":
        values.update(
            agent_version=AGENT_VERSION,
            launcher_version=AGENT_VERSION,
        )
    return compatibility_agent_hello().model_copy(update=values)


def _create_transport(
    settings: object,
    credential: str,
    executor: RuntimeExecutor,
    *,
    state: "_EndpointHttpPullState | None" = None,
) -> GatewayTransport:
    if not isinstance(settings, RuntimeSettings):
        raise GatewayTerminalError("invalid runtime settings")
    if settings.transport_mode == "gateway_wss":
        runtime_state = state or _EndpointHttpPullState()
        primary = WebSocketGatewayTransport(
            ca_file=settings.ca_file,
            credential=credential,
            endpoint_origin=settings.endpoint_origin,
        )
        if not settings.migration_http_pull_fallback:
            return primary
        fallback = ClassifiedGatewayTransport(
            _create_http_pull_transport(
                settings,
                credential,
                state=runtime_state,
            )
        )
        return MigrationFallbackGatewayTransport(
            primary=primary,
            fallback=fallback,
            enabled=True,
            endpoint_origin=settings.endpoint_origin,
            fallback_origin=settings.endpoint_origin,
        )
    if settings.transport_mode != "gateway_http_pull":
        raise GatewayTerminalError("unsupported Endpoint transport mode")
    return ClassifiedGatewayTransport(
        _create_http_pull_transport(
            settings,
            credential,
            state=state or _EndpointHttpPullState(),
        )
    )


async def _periodic_https_update_checks(
    settings: RuntimeSettings,
    credential: str,
    state: "_EndpointHttpPullState",
    *,
    sleep=asyncio.sleep,
) -> None:
    """Check immutable HTTPS updates while one WSS control session is alive."""
    while True:
        transport = ClassifiedGatewayTransport(
            _create_http_pull_transport(settings, credential, state=state)
        )
        try:
            await transport.connect(compatibility_agent_hello())
        finally:
            await transport.close()
        await sleep(endpoint_gateway.GATEWAY_UPDATE_POLL_INTERVAL_SEC)


async def _periodic_windows_update_checks(
    settings: RuntimeSettings,
    credential: str,
    *,
    sleep=asyncio.sleep,
) -> None:
    """Stage Windows updates over HTTPS while WSS remains the sole command channel."""
    await _run_windows_startup_report(settings, credential)
    while True:
        result = await _run_windows_update_check(settings, credential)
        if result == "scheduled":
            from pc_agent.version import EXIT_UPDATE_PENDING

            raise SystemExit(EXIT_UPDATE_PENDING)
        await sleep(endpoint_gateway.GATEWAY_UPDATE_POLL_INTERVAL_SEC)


async def _run_windows_startup_report(
    settings: RuntimeSettings, credential: str
) -> bool:
    """Deliver a post-WSS applied result without granting the updater network access."""
    from pc_agent.platform.windows.acl import PyWin32AclAdapter
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.transport.http_pull import reject_endpoint_redirect
    from pc_agent.update_adapter import EndpointUpdateAdapter

    context = ssl.create_default_context(cafile=str(settings.ca_file))
    connector = aiohttp.TCPConnector(ssl=context)
    trace = aiohttp.TraceConfig()
    trace.on_request_redirect.append(reject_endpoint_redirect)
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=20),
        connector=connector,
        trace_configs=[trace],
    ) as session:
        adapter = EndpointUpdateAdapter(
            api_url=settings.endpoint_origin,
            bearer_token=lambda: credential,
            session=session,
            data_root=settings.data_root,
        )
        runtime = WindowsOnlineUpdateRuntime(
            adapter=adapter,
            paths=WindowsUpdatePaths(
                settings.install_root, settings.data_root / "updates" / "pending_update.json"
            ),
            acl=PyWin32AclAdapter(),
            download=lambda *_args: _unexpected_windows_startup_download(),
        )
        return await runtime.report_startup_outcome()


async def _unexpected_windows_startup_download() -> tuple[str, int]:
    raise RuntimeError("startup report must not download an update artifact")


async def _run_windows_update_check(
    settings: RuntimeSettings, credential: str
) -> str:
    """Use the configured CA and Endpoint origin for the unprivileged update stager."""
    from pc_agent.endpoint_gateway import _download_gateway_artifact
    from pc_agent.platform.windows.acl import PyWin32AclAdapter
    from pc_agent.platform.windows.online_update_runtime import WindowsOnlineUpdateRuntime
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.transport.http_pull import reject_endpoint_redirect
    from pc_agent.update_adapter import EndpointUpdateAdapter

    context = ssl.create_default_context(cafile=str(settings.ca_file))
    connector = aiohttp.TCPConnector(ssl=context)
    trace = aiohttp.TraceConfig()
    trace.on_request_redirect.append(reject_endpoint_redirect)
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=20),
        connector=connector,
        trace_configs=[trace],
    ) as session:
        adapter = EndpointUpdateAdapter(
            api_url=settings.endpoint_origin,
            bearer_token=lambda: credential,
            session=session,
            data_root=settings.data_root,
        )
        runtime = WindowsOnlineUpdateRuntime(
            adapter=adapter,
            paths=WindowsUpdatePaths(
                settings.install_root, settings.data_root / "updates" / "pending_update.json"
            ),
            acl=PyWin32AclAdapter(),
            download=lambda item, destination: _download_gateway_artifact(
                session,
                item,
                destination,
                endpoint_origin=settings.endpoint_origin,
                credential_source=lambda: credential,
            ),
        )
        return (await runtime.run_once()).status


def _create_http_pull_transport(
    settings: RuntimeSettings,
    credential: str,
    *,
    state: "_EndpointHttpPullState",
) -> GatewayTransport:
    loop = asyncio.get_running_loop()
    poll_updates = loop.time() >= state.next_update_poll_at

    def update_poll_completed() -> None:
        state.next_update_poll_at = (
            loop.time() + endpoint_gateway.GATEWAY_UPDATE_POLL_INTERVAL_SEC
        )

    return endpoint_gateway.create_http_pull_transport(
        ca_file=settings.ca_file,
        credential=credential,
        endpoint_origin=settings.endpoint_origin,
        data_root=settings.data_root,
        current_selector=settings.install_root / "current.json",
        poll_updates=poll_updates,
        on_update_poll_complete=update_poll_completed,
    )


@dataclass(slots=True)
class _EndpointHttpPullState:
    next_update_poll_at: float = 0.0
