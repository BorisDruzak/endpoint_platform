from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.datastructures import Address, Headers

from endpoint_server.config import Settings
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import (
    AuditEvent,
    Command,
    CommandDelivery,
    CommandResult,
    Device,
    DeviceCredential,
    DeviceInstance,
    DeviceSession,
)
from endpoint_server.enrollment.credentials import device_token_digest


PEPPER = b"gateway-device-pepper"
VALID_TOKEN = "gateway-valid-device-token"


def gateway_settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=PEPPER,
        service_token_pepper=b"service-pepper",
        session_secret=b"session-secret",
        allowed_agent_cidrs=(ipaddress.ip_network("192.168.101.0/24"),),
        allowed_admin_cidrs=(),
        artifact_root=Path("artifacts"),
        trusted_proxy_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
    )


@pytest_asyncio.fixture
async def session_provider(
    tmp_path: Path,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    database_path = tmp_path / "gateway.sqlite3"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path.as_posix()}")
    tables = (
        Device.__table__,
        DeviceCredential.__table__,
        DeviceInstance.__table__,
        DeviceSession.__table__,
        Command.__table__,
        CommandDelivery.__table__,
        CommandResult.__table__,
        ContextCollection.__table__,
        AuditEvent.__table__,
    )
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(sync, tables=tables)
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def seed_device(
    session_provider: async_sessionmaker[AsyncSession],
    *,
    token: str = VALID_TOKEN,
    revoked: bool = False,
) -> Device:
    from datetime import UTC, datetime

    async with session_provider() as session:
        device = Device(
            id=uuid4(),
            device_identifier=f"device-{uuid4().hex}",
            display_name="Gateway test device",
        )
        session.add(device)
        await session.flush()
        session.add(
            DeviceCredential(
                id=uuid4(),
                device_id=device.id,
                credential_identifier=f"credential-{uuid4().hex}",
                token_digest=device_token_digest(token, PEPPER),
                pending_token_digest=None,
                rotation_overlap_expires_at=None,
                expires_at=None,
                revoked_at=datetime.now(UTC) if revoked else None,
            )
        )
        await session.commit()
        return device


@dataclass
class FakeGatewaySocket:
    session_provider: async_sessionmaker[AsyncSession]
    token: str = VALID_TOKEN
    peer: str = "127.0.0.1"
    source: str = "192.168.101.20"
    forwarded_proto: str | None = "https"
    scheme: str = "ws"

    def __post_init__(self) -> None:
        raw_headers = [
            (b"authorization", f"Bearer {self.token}".encode("ascii")),
            (b"x-forwarded-for", self.source.encode("ascii")),
        ]
        if self.forwarded_proto is not None:
            raw_headers.append(
                (b"x-forwarded-proto", self.forwarded_proto.encode("ascii"))
            )
        self.headers = Headers(raw=raw_headers)
        self.client = Address(self.peer, 443)
        self.scope = {"scheme": self.scheme}
        self.app = SimpleNamespace(
            state=SimpleNamespace(
                settings=gateway_settings(),
                session_provider=self.session_provider,
            )
        )


def agent_hello(device_id: UUID, *, instance_id: UUID | None = None) -> dict[str, object]:
    return {
        "schema_version": "agent_hello_v1",
        "device_id": str(device_id),
        "agent_instance_id": str(instance_id or uuid4()),
        "agent_version": "4.0.0",
        "launcher_version": "2.0.0",
        "platform": "linux_amd64",
        "boot_id": "boot-gateway-test",
        "capabilities": ["context.baseline.collect"],
        "last_result_sequence": 0,
        "last_policy_revision": 0,
    }
