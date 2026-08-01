"""Composition root for the neutral headless Endpoint Agent."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pc_agent import endpoint_gateway
from pc_agent.device_credential import DeviceCredentialError, read_device_credential
from pc_agent.transport.base import GatewayTerminalError, GatewayTransport
from pc_agent.transport.http_pull import ClassifiedGatewayTransport
from pc_agent.transport.protocol import (
    GatewayHelloV1,
    compatibility_agent_hello,
)
from pc_agent.transport.websocket import (
    MigrationFallbackGatewayTransport,
    WebSocketGatewayTransport,
)

from .command_executor import CommandExecutor
from .lifecycle import (
    CredentialRejected,
    RuntimeDependencies,
    RuntimeExecutor,
    RuntimeLifecycle,
)
from .status import RuntimeStatus


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    data_root: Path
    install_root: Path
    ca_file: Path
    endpoint_origin: str
    transport_mode: Literal["gateway_wss", "gateway_http_pull"]
    migration_http_pull_fallback: bool = False

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
        if not self.ca_file.is_file():
            raise ValueError("Endpoint CA file is missing")


class RuntimeApplication:
    def __init__(
        self,
        settings: RuntimeSettings,
        dependencies: RuntimeDependencies | None = None,
    ) -> None:
        self.settings = settings
        self.dependencies = dependencies or _default_dependencies()
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


def _default_dependencies() -> RuntimeDependencies:
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

    return RuntimeDependencies(
        load_credential=_load_credential,
        create_executor=CommandExecutor,
        create_transport=create_transport,
    )


def _load_credential(settings: object) -> str:
    if not isinstance(settings, RuntimeSettings):
        raise CredentialRejected("invalid runtime settings")
    try:
        return read_device_credential(settings.data_root / "device-credential")
    except DeviceCredentialError as error:
        raise CredentialRejected(str(error)) from error


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
            on_connected=_https_update_hook(
                settings,
                credential,
                state=runtime_state,
            ),
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


def _https_update_hook(
    settings: RuntimeSettings,
    credential: str,
    *,
    state: "_EndpointHttpPullState",
):
    async def poll_updates(_gateway_hello: GatewayHelloV1) -> None:
        transport = ClassifiedGatewayTransport(
            _create_http_pull_transport(settings, credential, state=state)
        )
        try:
            await transport.connect(compatibility_agent_hello())
        finally:
            await transport.close()

    return poll_updates


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
