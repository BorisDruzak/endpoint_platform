"""Disposable loopback server for real Console browser contract tests."""

from __future__ import annotations

import asyncio
import hashlib
import tempfile
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from uuid import UUID, uuid4

import uvicorn
from fastapi import HTTPException
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import JSON, DateTime, TypeDecorator, select, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

from endpoint_server.auth.passwords import hash_password
from endpoint_server.config import Settings
from endpoint_server.context.models import ContextCurrent, ContextSnapshot
from endpoint_server.db.base import Base
from endpoint_server.db.models import (
    AdminUser, Device, EndpointOperation, ModuleOperationStep,
    ServiceClient, UpdateBuild, UpdateRollout, UpdateTarget, WindowsSetupRelease,
)
from endpoint_server.enrollment.campaigns import issue_campaign
from endpoint_server.enrollment.requests import CampaignSelection, build_enrollment_request
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_server.main import create_app


@compiles(ARRAY, "sqlite")
def _array_as_json(*_args: object, **_kwargs: object) -> str:
    return "JSON"


@compiles(JSONB, "sqlite")
def _jsonb_as_json(*_args: object, **_kwargs: object) -> str:
    return "JSON"


class _UTCDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, _dialect: object) -> datetime | None:
        return value.astimezone(UTC).replace(tzinfo=None) if value is not None else None

    def process_result_value(self, value: datetime | None, _dialect: object) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


async def _serve(root: Path) -> None:
    database = root / "console-e2e.sqlite"
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, ARRAY):
                column.type = JSON()
            elif isinstance(column.type, DateTime) and column.type.timezone:
                column.type = _UTCDateTime()
    engine = create_async_engine(f"sqlite+aiosqlite:///{database.as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        # SQLite ignores postgresql_where and creates an unconditional unique index.
        await connection.execute(text("DROP INDEX uq_update_targets_active_device"))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    setup_name = "EndpointAgentSetup-3.2.63-x64.exe"
    setup_content = b"disposable browser test setup artifact"
    (root / setup_name).write_bytes(setup_content)
    async with sessions() as session:
        session.add(AdminUser(
            username="console-e2e", password_digest=hash_password("console-e2e-password"),
            scopes=["updates:write"],
        ))
        device = Device(device_identifier="console-e2e-device", display_name="Тестовый компьютер")
        lab_device = Device(device_identifier="console-e2e-lab", display_name="Лабораторный Agent")
        owner = ServiceClient(client_identifier="endpoint-console-internal", display_name="Console")
        build = UpdateBuild(
            build_identifier="console-e2e-build", version="3.2.63", platform="windows_amd64",
            channel="stable", artifact_identifier="console-e2e-artifact",
            artifact_url="https://example.test/agent.zip", artifact_name="agent.zip",
            archive_type="zip", sha256_digest="a" * 64, size=1024,
        )
        previous_build = UpdateBuild(
            build_identifier="console-e2e-previous-build", version="3.2.62", platform="windows_amd64",
            channel="stable", artifact_identifier="console-e2e-previous-artifact",
            artifact_url="https://example.test/previous-agent.zip", artifact_name="previous-agent.zip",
            archive_type="zip", sha256_digest="b" * 64, size=1024,
        )
        setup_release = WindowsSetupRelease(
            version="3.2.63", agent_version="3.2.63",
            artifact_identifier=setup_name, filename=setup_name,
            setup_sha256=hashlib.sha256(setup_content).hexdigest(),
            msi_sha256="b" * 64, source_commit="c" * 40,
            msi_source_commit="d" * 40,
            authenticode_status="unsigned", msi_authenticode_status="unsigned",
        )
        session.add_all([device, lab_device, owner, build, previous_build, setup_release])
        await session.flush()
        snapshot = ContextSnapshot(
            id=uuid4(), collection_id=uuid4(), device_id=device.id,
            profile="inventory_v1", collected_at=now, raw_payload={},
            normalized_projection={
                "schema_version": "device_context_v1", "profile": "inventory_v1",
                "collected_at": now.isoformat(), "warnings": [],
                "sections": {
                    "system": {"hostname": "console-e2e-device", "platform": "windows", "os_name": "Windows 11", "os_version": "11"},
                    "hardware": {"cpu_model": "Sample CPU"},
                    "memory": {"total_bytes": 17179869184, "module_count": 0, "modules": []},
                    "storage": {"physical_devices": []}, "interfaces": [],
                },
            },
        )
        session.add(snapshot)
        await session.flush()
        session.add(ContextCurrent(
            device_id=device.id, profile="inventory_v1", snapshot_id=snapshot.id,
            updated_at=now,
        ))
        rollout = UpdateRollout(
            rollout_identifier="console-e2e-rollout", build_id=build.id, mode="canary",
            reason="Проверка консоли", status="completed", started_at=now,
            completed_at=now,
        )
        session.add(rollout)
        await session.flush()
        session.add(UpdateTarget(
            rollout_id=rollout.id, device_id=device.id,
            target_identifier="console-e2e-target", operation_id="console-e2e-update-operation",
            status="applied", assigned_at=now, terminal_at=now,
        ))
        campaign = issue_campaign(
            b"disposable-browser-test-pepper",
            expires_at=now + timedelta(days=1), max_uses=2,
            allowed_cidrs=("192.0.2.0/24",), target_platform="windows",
            policy={
                "policy_id": "console-e2e-manual", "enrollment_mode": "manual",
                "allowed_installer_releases": ["3.2.63"],
            },
            label="Тестовая ручная кампания", now=now,
        ).record
        session.add(campaign)
        session.add(build_enrollment_request(
            installation_id="win-00112233-4455-6677-8899-aabbccddeeff",
            hardware_fingerprint="sha256:browser-test-fingerprint",
            request_capability="a" * 43,
            source_address=IPv4Address("192.0.2.10"),
            installer_version="3.2.63", installer_release_id="3.2.63",
            hostname="Тестовая заявка",
            selection=CampaignSelection("waiting_approval", campaign, "MANUAL_POLICY"),
            pepper=b"disposable-browser-test-pepper", now=now,
            manufacturer="Тест", model="Рабочая станция",
            macs=("00:11:22:33:44:55",),
        ))
        await session.commit()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{database.as_posix()}",
        public_base_url="https://endpoint.sosnadmin.local",
        device_token_pepper=b"disposable-browser-test-pepper",
        service_token_pepper=b"disposable-browser-test-pepper",
        session_secret=b"disposable-browser-test-session",
        allowed_agent_cidrs=(), allowed_admin_cidrs=(), artifact_root=root,
        endpoint_module_platform_enabled=True,
        endpoint_module_execution_enabled=True,
        endpoint_network_primitives_enabled=True,
        endpoint_operations_api_enabled=True,
        endpoint_network_probe_allowed_suffixes=(".example.test",),
    )
    app = create_app(settings, session_provider=sessions)
    await app.state.gateway_connection_registry.register(GatewayConnection(
        lab_device.id, lab_device.id, object(), agent_version="3.2.63",
        platform="linux_amd64", effective_capabilities=frozenset({"dns.resolve"}),
    ))

    async def complete_simulated_operation(operation_id: UUID) -> dict[str, str]:
        """Test-only Agent result injection; production has no such route."""
        async with sessions() as session:
            operation = await session.get(EndpointOperation, operation_id)
            if (operation is None or operation.device_id != lab_device.id
                    or operation.status != "queued"
                    or operation.parameters not in ({"execution_mode": "lab"}, {"execution_mode": "published"})):
                raise HTTPException(status_code=409, detail="Expected a queued test module operation")
            steps = (await session.scalars(
                select(ModuleOperationStep).where(ModuleOperationStep.operation_id == operation.id)
            )).all()
            if len(steps) != 1 or steps[0].capability != "dns.resolve":
                raise HTTPException(status_code=409, detail="Expected one DNS step")
            completed_at = datetime.now(UTC)
            if operation.parameters["execution_mode"] == "lab":
                operation.parameters = {**operation.parameters, "execution_platform": "linux_amd64"}
            operation.status = "succeeded"
            operation.completed_at = completed_at
            steps[0].status = "succeeded"
            steps[0].started_at = completed_at
            steps[0].completed_at = completed_at
            steps[0].safe_result_json = {
                "schema_version": "dns_resolve_result_v1",
                "target": "api.example.test", "addresses": [],
                "address_count": 0, "status": "succeeded",
                "collected_at": completed_at.isoformat(),
            }
            await session.commit()
        return {"status": "succeeded"}

    app.add_api_route("/__test__/complete-module-operation/{operation_id}", complete_simulated_operation, methods=["POST"])

    async def complete_simulated_rollout(rollout_id: UUID) -> dict[str, str]:
        """Test-only applied target injection; production has no such route."""
        async with sessions() as session:
            rollout = await session.get(UpdateRollout, rollout_id)
            targets = (await session.scalars(
                select(UpdateTarget).where(UpdateTarget.rollout_id == rollout_id)
            )).all()
            if rollout is None or rollout.status != "active" or rollout.mode != "canary" or len(targets) != 1 or targets[0].status != "assigned":
                raise HTTPException(status_code=409, detail="Expected one active canary target")
            completed_at = datetime.now(UTC)
            rollout.status = "completed"
            rollout.completed_at = completed_at
            targets[0].status = "applied"
            targets[0].terminal_at = completed_at
            targets[0].updated_at = completed_at
            await session.commit()
        return {"status": "completed"}

    app.add_api_route("/__test__/complete-rollout/{rollout_id}", complete_simulated_rollout, methods=["POST"])
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = root / "cert.pem", root / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=8765, log_level="warning",
        ssl_certfile=str(cert_path), ssl_keyfile=str(key_path),
    ))
    try:
        await server.serve()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="endpoint-console-e2e-") as directory:
        asyncio.run(_serve(Path(directory)))
