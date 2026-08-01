"""Composition root for the neutral headless Endpoint Agent."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import aiohttp

from pc_agent import endpoint_gateway

from .command_executor import CommandExecutor
from .lifecycle import (
    CredentialRejected,
    RetryableTransportError,
    RuntimeDependencies,
    RuntimeExecutor,
    RuntimeLifecycle,
    TerminalTransportError,
)
from .status import RuntimeStatus


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    data_root: Path
    install_root: Path
    ca_file: Path
    endpoint_origin: str
    transport_mode: Literal["gateway_wss", "gateway_http_pull"]

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
    return RuntimeDependencies(
        load_credential=_load_credential,
        create_executor=CommandExecutor,
        create_transport=_create_transport,
    )


def _load_credential(settings: object) -> str:
    if not isinstance(settings, RuntimeSettings):
        raise CredentialRejected("invalid runtime settings")
    path = settings.data_root / "device-credential"
    try:
        raw = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise CredentialRejected("Endpoint device credential is unavailable") from error
    credential = raw.rstrip("\r\n")
    if (
        raw not in {credential, f"{credential}\n"}
        or len(credential) != 43
        or not credential.isascii()
        or any(character.isspace() for character in credential)
    ):
        raise CredentialRejected("Endpoint device credential is invalid")
    return credential


def _create_transport(
    settings: object,
    credential: str,
    executor: RuntimeExecutor,
) -> "_EndpointHttpPullTransport":
    if not isinstance(settings, RuntimeSettings):
        raise TerminalTransportError("invalid runtime settings")
    if settings.transport_mode != "gateway_http_pull":
        raise TerminalTransportError(
            "Gateway WSS is not available before the transport migration"
        )
    if settings.endpoint_origin != endpoint_gateway._ORIGIN:
        raise TerminalTransportError(
            "current HTTP pull supports only the accepted Endpoint origin"
        )
    return _EndpointHttpPullTransport(settings, credential, executor)


class _EndpointHttpPullTransport:
    """Transitional seam around the accepted HTTP-pull Gateway runtime."""

    def __init__(
        self,
        settings: RuntimeSettings,
        credential: str,
        executor: RuntimeExecutor,
    ) -> None:
        self._settings = settings
        self._credential = credential
        self._executor = executor

    async def start(self) -> None:
        try:
            await endpoint_gateway.run_gateway_forever(
                ca_file=self._settings.ca_file,
                command_executor=self._executor,
                credential=self._credential,
                endpoint_origin=self._settings.endpoint_origin,
                data_root=self._settings.data_root,
                current_selector=self._settings.install_root / "current.json",
            )
        except endpoint_gateway.GatewayCredentialRejected as error:
            raise CredentialRejected(str(error)) from error
        except (
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientConnectorSSLError,
        ) as error:
            raise TerminalTransportError(type(error).__name__) from error
        except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as error:
            raise RetryableTransportError(type(error).__name__) from error
        except SystemExit:
            raise
        except Exception as error:
            raise TerminalTransportError(type(error).__name__) from error

    async def close(self) -> None:
        return None
