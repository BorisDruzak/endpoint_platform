"""Feature-gated service API for the Endpoint Operation v1 boundary."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import ipaddress
import json
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
import yaml
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from endpoint_server.auth.scopes import ServicePrincipal
from endpoint_server.config import Settings
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.gateway.connection_registry import GatewayConnection
from endpoint_server.db.models import (
    AuditEvent,
    Command,
    CommandResult,
    Device,
    DeviceInstance,
    EndpointOperation,
    ModuleDefinition,
    ModuleLiveTest,
    ModuleOperationStep,
    ModuleValidationRun,
    ModuleVersion,
    ServiceClient,
    ServiceCredential,
)
from endpoint_server.http import correlation
from endpoint_server.main import create_app
from endpoint_server.operations.projection import project_diagnostic_result
from pc_agent.context_profiles.diagnostic import collect_diagnostic
from pc_agent.context_profiles.probe import JOURNAL_COMMAND, PROCESS_COMMAND


CREATE_BODY = {
    "schema_version": "endpoint_operation_create_v1",
    "capability": "context.diagnostic.collect",
    "parameters": {"reason": "Collect bounded diagnostic context"},
}
IDEMPOTENCY_KEY = "operation-route-key-0001"
MODULE_CREATE_BODY = {
    "schema_version": "module_version_create_v1",
    "display_name": "Network",
    "version": "1.0.0",
    "recipe": {
        "schema_version": "endpoint_recipe_module_v1",
        "module_key": "network.basic.check",
        "supported_platforms": ["linux_amd64"],
        "inputs": [{"name": "target", "value_type": "string"}],
        "steps": [
            {
                "step_id": "dns",
                "capability": "dns.resolve",
                "parameters": {
                    "target": {"kind": "input", "name": "target"},
                    "family": {"kind": "literal", "value": "any"},
                },
            }
        ],
    },
}


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("GET", "/api/v1/devices/one-segment"),
        ("GET", "/api/v1/devices/one-segment/capabilities"),
        ("POST", "/api/v1/devices/one-segment/operations"),
        ("POST", "/api/v1/devices/one-segment/module-operations"),
        ("GET", "/api/v1/module-operations/one-segment"),
        ("GET", "/api/v1/operations/one-segment"),
    ),
)
def test_operation_api_request_recognizes_only_contract_route_shapes(
    method: str,
    path: str,
) -> None:
    assert correlation.is_operation_api_request(method, path)


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("POST", "/api/v1/devices/one-segment"),
        ("GET", "/api/v1/devices/one-segment/operations"),
        ("POST", "/api/v1/operations/one-segment"),
        ("GET", "/api/v1/devices"),
        ("GET", "/api/v1/devices/network-identities"),
        ("GET", "/api/v1/devices/one-segment/context"),
        ("GET", "/api/v1/devices/one-segment/context/history"),
        ("GET", "/api/v1/devices/one-segment/updates"),
    ),
)
def test_operation_api_request_excludes_unrelated_or_wrong_method_paths(
    method: str,
    path: str,
) -> None:
    assert not correlation.is_operation_api_request(method, path)


def _settings(
    *,
    enabled: bool,
    network_primitives_enabled: bool = False,
    module_platform_enabled: bool = False,
    module_execution_enabled: bool = False,
) -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        public_base_url="https://endpoint.sosnadmin.local",
        session_secret=b"session-secret",
        service_token_pepper=b"service-pepper",
        device_token_pepper=b"device-pepper",
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_admin_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
        artifact_root=Path("artifacts"),
        endpoint_operations_api_enabled=enabled,
        endpoint_network_primitives_enabled=network_primitives_enabled,
        endpoint_network_probe_allowed_cidrs=(
            (ipaddress.ip_network("10.20.0.0/16"),)
            if network_primitives_enabled
            else ()
        ),
        endpoint_module_platform_enabled=module_platform_enabled,
        endpoint_module_execution_enabled=module_execution_enabled,
    )


def _credential(client: ServiceClient, scopes: list[str]) -> ServiceCredential:
    return ServiceCredential(
        id=uuid4(),
        service_client_id=client.id,
        credential_identifier=uuid4().hex,
        token_prefix="svc_" + uuid4().hex,
        secret_digest="digest",
        scopes=scopes,
        expires_at=None,
        revoked_at=None,
    )


@dataclass(frozen=True, slots=True)
class RouteFixture:
    session_provider: async_sessionmaker[AsyncSession]
    owner: ServiceClient
    foreign: ServiceClient
    device: Device
    other_device: Device
    principals: dict[str, ServicePrincipal]


@pytest_asyncio.fixture
async def route_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RouteFixture]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        ServiceClient.__table__,
        Device.__table__,
        DeviceInstance.__table__,
        Command.__table__,
        CommandResult.__table__,
        AuditEvent.__table__,
        ContextCollection.__table__,
        ContextSnapshot.__table__,
        EndpointOperation.__table__,
        ModuleDefinition.__table__,
        ModuleLiveTest.__table__,
        ModuleOperationStep.__table__,
        ModuleValidationRun.__table__,
        ModuleVersion.__table__,
    )
    async with engine.begin() as connection:
        await connection.execute(text("PRAGMA foreign_keys=ON"))
        await connection.run_sync(
            lambda sync: Device.metadata.create_all(sync, tables=tables)
        )
    provider = async_sessionmaker(engine, expire_on_commit=False)
    owner = ServiceClient(
        id=uuid4(),
        client_identifier="helpdesk",
        display_name="Helpdesk",
        disabled_at=None,
    )
    foreign = ServiceClient(
        id=uuid4(),
        client_identifier="foreign-service",
        display_name="Foreign service",
        disabled_at=None,
    )
    device = Device(
        id=uuid4(),
        device_identifier="route-device",
        display_name="Route device",
        retired_at=None,
    )
    other_device = Device(
        id=uuid4(),
        device_identifier="other-route-device",
        display_name="Other route device",
        retired_at=None,
    )
    async with provider() as session:
        session.add_all((owner, foreign, device, other_device))
        await session.commit()
    principals = {
        "devices-reader": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["devices.read"]),
        ),
        "creator-old": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["operations.create"]),
        ),
        "reader-rotated": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["operations.read"]),
        ),
        "modules-writer": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["modules.write"]),
        ),
        "modules-reader": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["modules.read"]),
        ),
        "modules-validator": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["modules.validate"]),
        ),
        "modules-publisher": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["modules.publish"]),
        ),
        "module-operator": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["module_operations.create"]),
        ),
        "module-reader": ServicePrincipal(
            client=owner,
            credential=_credential(owner, ["module_operations.read"]),
        ),
        "foreign-reader": ServicePrincipal(
            client=foreign,
            credential=_credential(foreign, ["operations.read"]),
        ),
    }

    import endpoint_server.auth.scopes as scopes_module

    async def load(_: AsyncSession, token: str, __: bytes) -> ServicePrincipal | None:
        return principals.get(token)

    monkeypatch.setattr(scopes_module, "_load_service_principal", load)
    yield RouteFixture(
        session_provider=provider,
        owner=owner,
        foreign=foreign,
        device=device,
        other_device=other_device,
        principals=principals,
    )
    await engine.dispose()


def _client(route_fixture: RouteFixture, *, enabled: bool = True) -> httpx.AsyncClient:
    app = create_app(_settings(enabled=enabled), route_fixture.session_provider)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    )


def _authorization(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Correlation-ID": "test-correlation-id",
    }


@pytest.mark.asyncio
async def test_module_catalog_echoes_safe_correlation_for_external_adapter(
    route_fixture: RouteFixture,
) -> None:
    """The typed Helpdesk adapter rejects a module response without correlation."""
    app = create_app(
        _settings(enabled=False, module_platform_enabled=True),
        route_fixture.session_provider,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.get(
            "/api/v1/modules",
            headers=_authorization("modules-reader"),
        )

    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == "test-correlation-id"
    assert response.json() == {"data": []}


def _create_headers(token: str) -> dict[str, str]:
    return {
        **_authorization(token),
        "Idempotency-Key": IDEMPOTENCY_KEY,
        "X-Correlation-ID": str(uuid4()),
    }


def _diagnostic_projection(
    *,
    completed_at: datetime,
    reason: str = CREATE_BODY["parameters"]["reason"],
    processes: list[dict[str, str]] | None = None,
    log_excerpt: str | None = "Bearer authentication was redacted.",
) -> dict[str, object]:
    return {
        "schema_version": "device_context_v1",
        "profile": "diagnostic_v1",
        "collected_at": completed_at.isoformat(),
        "warnings": ["redaction_applied"],
        "sections": {
            "reason": reason,
            "processes": processes
            if processes is not None
            else [{"name": "endpoint-agent", "state": "running"}],
            "log_excerpt": log_excerpt,
        },
    }


async def _complete_operation(
    route_fixture: RouteFixture,
    operation_id: str,
    *,
    normalized_projection: dict[str, object],
) -> tuple[EndpointOperation, ContextCollection, ContextSnapshot]:
    completed_at = datetime.now(UTC)
    async with route_fixture.session_provider() as session:
        operation = await session.get(EndpointOperation, UUID(operation_id))
        assert operation is not None
        collection = await session.get(
            ContextCollection, operation.context_collection_id
        )
        assert collection is not None
        operation.status = "succeeded"
        operation.completed_at = completed_at
        collection.status = "completed"
        collection.completed_at = completed_at
        snapshot = ContextSnapshot(
            id=uuid4(),
            collection_id=collection.id,
            device_id=route_fixture.device.id,
            profile="diagnostic_v1",
            collected_at=completed_at,
            semantic_hash="a" * 64,
            raw_payload={},
            normalized_projection=normalized_projection,
        )
        session.add(snapshot)
        await session.commit()
        return operation, collection, snapshot


@pytest.mark.asyncio
async def test_default_false_feature_flag_registers_no_operation_routes(
    route_fixture: RouteFixture,
) -> None:
    """A deployment that never opts in must not expose a working operation API."""
    app = create_app(_settings(enabled=False), route_fixture.session_provider)
    paths = app.openapi()["paths"]
    assert f"/api/v1/devices/{route_fixture.device.id}/operations" not in paths
    assert "/api/v1/devices/{device_id}/operations" not in paths
    assert "/api/v1/devices/{device_id}/capabilities" not in paths
    assert "/api/v1/operations/{operation_id}" not in paths

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        create = await client.post(
            f"/api/v1/devices/{route_fixture.device.id}/operations",
            json=CREATE_BODY,
            headers=_create_headers("creator-old"),
        )
        capabilities = await client.get(
            f"/api/v1/devices/{route_fixture.device.id}/capabilities",
            headers=_authorization("devices-reader"),
        )
        read = await client.get(
            f"/api/v1/operations/{uuid4()}",
            headers=_authorization("reader-rotated"),
        )

    assert [create.status_code, capabilities.status_code, read.status_code] == [
        404,
        404,
        404,
    ]


@pytest.mark.asyncio
async def test_capabilities_requires_devices_read_and_exposes_only_safe_availability(
    route_fixture: RouteFixture,
) -> None:
    """Adding session or agent internals to discovery must break this response."""
    path = f"/api/v1/devices/{route_fixture.device.id}/capabilities"
    async with _client(route_fixture) as client:
        unauthenticated = await client.get(path)
        wrong_scope = await client.get(path, headers=_authorization("creator-old"))
        allowed = await client.get(path, headers=_authorization("devices-reader"))

    assert unauthenticated.status_code == 401
    assert wrong_scope.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json() == {
        "data": {
            "schema_version": "endpoint_device_capabilities_v1",
            "device_id": str(route_fixture.device.id),
            "capabilities": [
                {
                    "capability": "context.diagnostic.collect",
                    "available": True,
                    "transport": "gateway_wss",
                    "risk": "read_only",
                    "consent_required": False,
                    "parameter_schema_version": ("diagnostic_collection_parameters_v1"),
                }
            ],
        }
    }
    for forbidden in {
        "session_id",
        "last_seen_at",
        "agent_version",
        "effective_capabilities",
    }:
        assert forbidden not in allowed.text


@pytest.mark.asyncio
async def test_capabilities_project_active_typed_network_primitive_without_connection_internals(
    route_fixture: RouteFixture,
) -> None:
    app = create_app(
        _settings(enabled=True, network_primitives_enabled=True),
        route_fixture.session_provider,
    )
    await app.state.gateway_connection_registry.register(
        GatewayConnection(
            device_id=route_fixture.device.id,
            session_id=uuid4(),
            websocket=object(),
            agent_version="3.2.27",
            platform="linux_amd64",
            effective_capabilities=frozenset({"network.ping"}),
        )
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.get(
            f"/api/v1/devices/{route_fixture.device.id}/capabilities",
            headers=_authorization("devices-reader"),
        )

    assert response.status_code == 200
    capabilities = response.json()["data"]["capabilities"]
    assert [item["capability"] for item in capabilities] == [
        "context.diagnostic.collect",
        "network.ping",
    ]
    assert "session_id" not in response.text
    assert "agent_version" not in response.text
    assert "effective_capabilities" not in response.text


@pytest.mark.asyncio
async def test_default_false_module_platform_flag_registers_no_module_routes(
    route_fixture: RouteFixture,
) -> None:
    app = create_app(
        _settings(enabled=True, module_platform_enabled=False),
        route_fixture.session_provider,
    )
    assert "/api/v1/modules/versions" not in app.openapi()["paths"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post("/api/v1/modules/versions")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_module_create_requires_dedicated_scope_and_persists_draft(
    route_fixture: RouteFixture,
) -> None:
    app = create_app(
        _settings(enabled=True, module_platform_enabled=True),
        route_fixture.session_provider,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        forbidden = await client.post(
            "/api/v1/modules/versions",
            json=MODULE_CREATE_BODY,
            headers=_authorization("creator-old"),
        )
        created = await client.post(
            "/api/v1/modules/versions",
            json=MODULE_CREATE_BODY,
            headers=_authorization("modules-writer"),
        )
    assert forbidden.status_code == 403
    assert created.status_code == 201
    assert created.json()["data"]["state"] == "draft"


@pytest.mark.asyncio
async def test_module_catalog_reads_are_scoped_and_return_only_recipe_metadata(
    route_fixture: RouteFixture,
) -> None:
    app = create_app(
        _settings(enabled=True, module_platform_enabled=True),
        route_fixture.session_provider,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        created = await client.post(
            "/api/v1/modules/versions",
            json=MODULE_CREATE_BODY,
            headers=_authorization("modules-writer"),
        )
        forbidden = await client.get(
            "/api/v1/modules", headers=_authorization("modules-writer")
        )
        listed = await client.get(
            "/api/v1/modules", headers=_authorization("modules-reader")
        )
        latest = await client.get(
            "/api/v1/modules/network.basic.check",
            headers=_authorization("modules-reader"),
        )
        exact = await client.get(
            "/api/v1/modules/network.basic.check/versions/1.0.0",
            headers=_authorization("modules-reader"),
        )

    assert created.status_code == 201
    assert forbidden.status_code == 403
    assert listed.json() == {
        "data": [{"module_key": "network.basic.check", "display_name": "Network"}]
    }
    assert latest.json() == exact.json()
    payload = exact.json()["data"]
    assert payload["module_key"] == "network.basic.check"
    assert payload["state"] == "draft"
    assert payload["recipe"] == MODULE_CREATE_BODY["recipe"]
    assert not {
        "command_id",
        "inputs",
        "idempotency_key",
        "service_client",
    }.intersection(json.dumps(payload))


@pytest.mark.asyncio
async def test_module_create_returns_safe_conflict_for_duplicate_version(
    route_fixture: RouteFixture,
) -> None:
    app = create_app(
        _settings(enabled=True, module_platform_enabled=True),
        route_fixture.session_provider,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        first = await client.post(
            "/api/v1/modules/versions",
            json=MODULE_CREATE_BODY,
            headers=_authorization("modules-writer"),
        )
        duplicate = await client.post(
            "/api/v1/modules/versions",
            json=MODULE_CREATE_BODY,
            headers=_authorization("modules-writer"),
        )
    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": {"code": "endpoint_module_version_conflict"}}


@pytest.mark.asyncio
async def test_module_validate_requires_dedicated_scope_and_returns_typed_result(
    route_fixture: RouteFixture,
) -> None:
    app = create_app(
        _settings(enabled=True, module_platform_enabled=True),
        route_fixture.session_provider,
    )
    validation_path = "/api/v1/modules/network.basic.check/versions/1.0.0/validate"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        created = await client.post(
            "/api/v1/modules/versions",
            json=MODULE_CREATE_BODY,
            headers=_authorization("modules-writer"),
        )
        forbidden = await client.post(
            validation_path,
            headers=_authorization("modules-writer"),
        )
        validated = await client.post(
            validation_path,
            headers=_authorization("modules-validator"),
        )

    assert created.status_code == 201
    assert forbidden.status_code == 403
    assert validated.status_code == 200
    assert validated.json()["data"] == {
        "schema_version": "module_validation_run_v1",
        "module_key": "network.basic.check",
        "version": "1.0.0",
        "status": "succeeded",
        "error_codes": [],
        "warning_codes": [],
        "completed_at": validated.json()["data"]["completed_at"],
    }
    async with route_fixture.session_provider() as session:
        events = list(
            (
                await session.scalars(
                    select(AuditEvent).order_by(AuditEvent.created_at)
                )
            ).all()
        )
    assert [
        (event.action, event.actor_kind, event.actor_identifier) for event in events
    ] == [
        ("endpoint.module_version_created", "service", "helpdesk"),
        ("endpoint.module_validation_completed", "service", "helpdesk"),
    ]
    assert all("recipe" not in json.dumps(event.details) for event in events)


@pytest.mark.asyncio
async def test_module_publish_requires_lab_evidence_and_dedicated_scope(
    route_fixture: RouteFixture,
) -> None:
    app = create_app(
        _settings(enabled=True, module_platform_enabled=True),
        route_fixture.session_provider,
    )
    version_path = "/api/v1/modules/network.basic.check/versions/1.0.0"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        created = await client.post(
            "/api/v1/modules/versions",
            json=MODULE_CREATE_BODY,
            headers=_authorization("modules-writer"),
        )
        validated = await client.post(
            f"{version_path}/validate",
            headers=_authorization("modules-validator"),
        )
        forbidden = await client.post(
            f"{version_path}/publish",
            headers=_authorization("modules-validator"),
        )

    assert created.status_code == 201
    assert validated.status_code == 200
    assert forbidden.status_code == 403
    async with route_fixture.session_provider() as session:
        module_version = await session.scalar(
            select(ModuleVersion)
            .join(ModuleDefinition)
            .where(
                ModuleDefinition.module_key == "network.basic.check",
                ModuleVersion.version == "1.0.0",
            )
        )
        assert module_version is not None
        completed_at = datetime.now(UTC)
        lab_operation = EndpointOperation(
            id=uuid4(),
            created_at=completed_at,
            requested_by_service_client_id=route_fixture.owner.id,
            device_id=route_fixture.device.id,
            idempotency_key="module-lab-operation-key",
            capability="endpoint.module.recipe",
            parameters={
                "execution_mode": "lab",
                "execution_platform": "linux_amd64",
            },
            correlation=None,
            status="succeeded",
            deadline_at=completed_at + timedelta(minutes=5),
            completed_at=completed_at,
            context_collection_id=None,
            command_id=None,
            module_version_id=module_version.id,
            module_inputs={"target": "endpoint-staging.sosnadmin.local"},
        )
        session.add(lab_operation)
        session.add(
            ModuleOperationStep(
                id=uuid4(),
                created_at=completed_at,
                operation_id=lab_operation.id,
                sequence=0,
                recipe_step_key="dns",
                capability="dns.resolve",
                status="succeeded",
                command_id=None,
                safe_result_json={"status": "succeeded"},
                error_code=None,
                started_at=completed_at,
                completed_at=completed_at,
            )
        )
        await session.flush()
        await session.commit()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        unrelated_live_test = await client.post(
            f"{version_path}/live-tests/{uuid4()}",
            json={"schema_version": "module_live_test_record_v1"},
            headers=_authorization("modules-validator"),
        )
        live_test = await client.post(
            f"{version_path}/live-tests/{lab_operation.id}",
            json={"schema_version": "module_live_test_record_v1"},
            headers=_authorization("modules-validator"),
        )
        forbidden_accept = await client.post(
            f"{version_path}/accept-labs",
            headers=_authorization("modules-validator"),
        )
        accepted = await client.post(
            f"{version_path}/accept-labs",
            headers=_authorization("modules-publisher"),
        )
        published = await client.post(
            f"{version_path}/publish",
            headers=_authorization("modules-publisher"),
        )
        deprecated = await client.post(
            f"{version_path}/deprecate",
            headers=_authorization("modules-publisher"),
        )

    assert unrelated_live_test.status_code == 409
    assert unrelated_live_test.json()["detail"] == {
        "code": "endpoint_module_live_test_conflict"
    }
    assert live_test.status_code == 201
    assert live_test.json()["data"] == {
        "schema_version": "module_live_test_recorded_v1",
        "module_key": "network.basic.check",
        "version": "1.0.0",
        "platform": "linux_amd64",
        "status": "passed",
        "tested_at": live_test.json()["data"]["tested_at"],
    }
    assert forbidden_accept.status_code == 403
    assert accepted.status_code == 200
    assert accepted.json()["data"]["state"] == "lab_accepted"
    assert published.status_code == 200
    assert published.json()["data"] == {
        "schema_version": "module_version_state_v1",
        "module_key": "network.basic.check",
        "version": "1.0.0",
        "state": "published",
    }
    assert deprecated.status_code == 200
    assert deprecated.json()["data"] == {
        "schema_version": "module_version_state_v1",
        "module_key": "network.basic.check",
        "version": "1.0.0",
        "state": "deprecated",
    }


@pytest.mark.asyncio
async def test_validated_module_lab_operation_route_is_scoped_and_creates_parent(
    route_fixture: RouteFixture,
) -> None:
    app = create_app(
        _settings(
            enabled=True,
            network_primitives_enabled=True,
            module_platform_enabled=True,
            module_execution_enabled=True,
        ),
        route_fixture.session_provider,
    )
    version_path = "/api/v1/modules/network.basic.check/versions/1.0.0"
    lab_path = f"{version_path}/lab-operations/{route_fixture.device.id}"
    headers = {
        **_authorization("modules-validator"),
        "Idempotency-Key": "module-lab-route-key-0001",
        "X-Correlation-ID": "module-lab-route-0001",
    }
    body = {
        "schema_version": "endpoint_module_lab_operation_create_v1",
        "inputs": {"target": "10.20.0.10"},
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        created = await client.post(
            "/api/v1/modules/versions",
            json=MODULE_CREATE_BODY,
            headers=_authorization("modules-writer"),
        )
        validated = await client.post(
            f"{version_path}/validate",
            headers=_authorization("modules-validator"),
        )
        forbidden = await client.post(
            lab_path, json=body, headers=_authorization("modules-writer")
        )
        lab = await client.post(lab_path, json=body, headers=headers)
        replay = await client.post(lab_path, json=body, headers=headers)

    assert created.status_code == 201
    assert validated.status_code == 200
    assert forbidden.status_code == 403
    assert lab.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["data"]["operation_id"] == lab.json()["data"]["operation_id"]
    assert lab.json()["data"] == {
        "schema_version": "endpoint_module_operation_v1",
        "operation_id": lab.json()["data"]["operation_id"],
        "device_id": str(route_fixture.device.id),
        "module_key": "network.basic.check",
        "version": "1.0.0",
        "status": "queued",
        "created_at": lab.json()["data"]["created_at"],
        "deadline_at": lab.json()["data"]["deadline_at"],
        "completed_at": None,
    }


@pytest.mark.asyncio
async def test_module_operation_execution_route_is_flagged_scoped_and_idempotent(
    route_fixture: RouteFixture,
) -> None:
    path = f"/api/v1/devices/{route_fixture.device.id}/module-operations"
    disabled = create_app(
        _settings(enabled=True, module_platform_enabled=True),
        route_fixture.session_provider,
    )
    assert (
        path.replace(str(route_fixture.device.id), "{device_id}")
        not in disabled.openapi()["paths"]
    )

    app = create_app(
        _settings(
            enabled=True,
            network_primitives_enabled=True,
            module_platform_enabled=True,
            module_execution_enabled=True,
        ),
        route_fixture.session_provider,
    )
    async with route_fixture.session_provider() as session:
        definition = ModuleDefinition(
            id=uuid4(),
            module_key="network.basic.check",
            display_name="Network",
        )
        version = ModuleVersion(
            id=uuid4(),
            module_definition_id=definition.id,
            version="1.0.0",
            recipe=MODULE_CREATE_BODY["recipe"],
            state="published",
        )
        session.add_all((definition, version))
        await session.commit()

    body = {
        "schema_version": "endpoint_module_operation_create_v1",
        "module_key": "network.basic.check",
        "version": "1.0.0",
        "inputs": {"target": "10.20.1.10"},
    }
    headers = {
        **_authorization("module-operator"),
        "Idempotency-Key": "module-operation-http-key",
        "X-Correlation-ID": "module-operation-1",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        forbidden = await client.post(
            path, json=body, headers={**headers, **_authorization("modules-writer")}
        )
        created = await client.post(path, json=body, headers=headers)
        replay = await client.post(path, json=body, headers=headers)
        read = await client.get(
            f"/api/v1/module-operations/{created.json()['data']['operation_id']}",
            headers={
                **_authorization("module-reader"),
                "X-Correlation-ID": "module-operation-read-1",
            },
        )

    assert forbidden.status_code == 403
    assert created.status_code == 201
    assert replay.status_code == 200
    assert created.headers["X-Correlation-ID"] == "module-operation-1"
    assert created.json()["data"] == {
        "schema_version": "endpoint_module_operation_v1",
        "operation_id": created.json()["data"]["operation_id"],
        "device_id": str(route_fixture.device.id),
        "module_key": "network.basic.check",
        "version": "1.0.0",
        "status": "queued",
        "created_at": created.json()["data"]["created_at"],
        "deadline_at": created.json()["data"]["deadline_at"],
        "completed_at": None,
    }
    assert replay.json() == created.json()
    assert read.status_code == 200
    assert read.headers["X-Correlation-ID"] == "module-operation-read-1"
    assert read.json()["data"]["steps"] == [
        {
            "sequence": 0,
            "capability": "dns.resolve",
            "status": "queued",
            "error_code": None,
            "safe_result": None,
        }
    ]
    assert not {"recipe", "inputs", "idempotency_key", "command_id"}.intersection(
        json.dumps(read.json())
    )


@pytest.mark.asyncio
async def test_device_read_and_capabilities_are_versioned_and_echo_correlation(
    route_fixture: RouteFixture,
) -> None:
    """The Helpdesk provider contract is strict and correlation is HTTP-only."""
    correlation_id = str(uuid4())
    headers = {
        **_authorization("devices-reader"),
        "X-Correlation-ID": correlation_id,
    }
    async with _client(route_fixture) as client:
        device = await client.get(
            f"/api/v1/devices/{route_fixture.device.id}",
            headers=headers,
        )
        capabilities = await client.get(
            f"/api/v1/devices/{route_fixture.device.id}/capabilities",
            headers=headers,
        )

    assert [device.status_code, capabilities.status_code] == [200, 200]
    assert device.headers["X-Correlation-ID"] == correlation_id
    assert capabilities.headers["X-Correlation-ID"] == correlation_id
    assert device.json() == {
        "data": {
            "schema_version": "endpoint_device_summary_v1",
            "device_id": str(route_fixture.device.id),
            "display_name": "Route device",
            "retired": False,
            "last_seen_at": None,
        }
    }
    assert capabilities.json() == {
        "data": {
            "schema_version": "endpoint_device_capabilities_v1",
            "device_id": str(route_fixture.device.id),
            "capabilities": [
                {
                    "capability": "context.diagnostic.collect",
                    "available": True,
                    "transport": "gateway_wss",
                    "risk": "read_only",
                    "consent_required": False,
                    "parameter_schema_version": ("diagnostic_collection_parameters_v1"),
                }
            ],
        }
    }


@pytest.mark.asyncio
async def test_create_requires_scope_and_idempotency_then_returns_201_and_200(
    route_fixture: RouteFixture,
) -> None:
    """Removing auth, the required key, or replay status semantics must fail."""
    path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        unauthenticated = await client.post(
            path, json=CREATE_BODY, headers={"Idempotency-Key": IDEMPOTENCY_KEY}
        )
        wrong_scope = await client.post(
            path, json=CREATE_BODY, headers=_create_headers("devices-reader")
        )
        missing_key = await client.post(
            path, json=CREATE_BODY, headers=_authorization("creator-old")
        )
        invalid_key = await client.post(
            path,
            json=CREATE_BODY,
            headers={
                **_authorization("creator-old"),
                "Idempotency-Key": "short",
            },
        )
        unsafe_keys = [
            await client.post(
                path,
                json=CREATE_BODY,
                headers={
                    **_authorization("creator-old"),
                    "Idempotency-Key": key,
                },
            )
            for key in (
                " leading-operation-key",
                "trailing-operation-key ",
                "operation-key-with-del\x7f",
            )
        ]
        first = await client.post(
            path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
        replay = await client.post(
            path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )

    assert unauthenticated.status_code == 401
    assert wrong_scope.status_code == 403
    assert missing_key.status_code == 422
    assert invalid_key.status_code == 422
    assert [response.status_code for response in unsafe_keys] == [422, 422, 422]
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert first.json()["data"]["result"] is None
    assert first.json()["data"]["operation"]["result_available"] is False


@pytest.mark.asyncio
async def test_operation_correlation_is_header_only_and_never_serialized(
    route_fixture: RouteFixture,
) -> None:
    """Helpdesk ticket/correlation data cannot enter an Endpoint operation body."""
    create_path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    create_correlation = str(uuid4())
    create_headers = {
        **_authorization("creator-old"),
        "Idempotency-Key": IDEMPOTENCY_KEY,
        "X-Correlation-ID": create_correlation,
    }
    async with _client(route_fixture) as client:
        rejected = await client.post(
            create_path,
            json={
                **CREATE_BODY,
                "correlation": {"source_entity_id": "helpdesk-ticket"},
            },
            headers=create_headers,
        )
        created = await client.post(
            create_path,
            json=CREATE_BODY,
            headers=create_headers,
        )
        operation_id = created.json()["data"]["operation"]["operation_id"]
        read_correlation = str(uuid4())
        read = await client.get(
            f"/api/v1/operations/{operation_id}",
            headers={
                **_authorization("reader-rotated"),
                "X-Correlation-ID": read_correlation,
            },
        )

    assert rejected.status_code == 422
    assert rejected.headers["X-Correlation-ID"] == create_correlation
    assert created.status_code == 201
    assert created.headers["X-Correlation-ID"] == create_correlation
    assert read.status_code == 200
    assert read.headers["X-Correlation-ID"] == read_correlation
    assert "correlation" not in created.json()["data"]["operation"]
    assert "correlation" not in read.json()["data"]["operation"]


@pytest.mark.asyncio
async def test_provider_errors_echo_received_correlation_header(
    route_fixture: RouteFixture,
) -> None:
    """A consumer can correlate failed provider calls without an error envelope field."""
    correlation_id = str(uuid4())
    headers = {
        **_authorization("devices-reader"),
        "X-Correlation-ID": correlation_id,
    }
    async with _client(route_fixture) as client:
        response = await client.get(
            f"/api/v1/devices/{uuid4()}",
            headers=headers,
        )

    assert response.status_code == 404
    assert response.headers["X-Correlation-ID"] == correlation_id
    assert response.json()["detail"] == {"code": "endpoint_operation_device_not_found"}


@pytest.mark.asyncio
async def test_invalid_correlation_is_rejected_without_reflection(
    route_fixture: RouteFixture,
) -> None:
    """Only the documented safe ASCII tracing grammar may cross HTTP boundaries."""
    unsafe_correlation = "helpdesk/ticket-42"
    async with _client(route_fixture) as client:
        response = await client.get(
            f"/api/v1/devices/{route_fixture.device.id}",
            headers={
                **_authorization("devices-reader"),
                "X-Correlation-ID": unsafe_correlation,
            },
        )

    assert response.status_code == 422
    assert "X-Correlation-ID" not in response.headers
    assert unsafe_correlation not in response.text


@pytest.mark.asyncio
async def test_operation_correlation_middleware_does_not_intercept_unrelated_route(
    route_fixture: RouteFixture,
) -> None:
    """The Operations-only policy must not alter another device API response."""
    unsafe_correlation = "helpdesk/ticket-42"
    async with _client(route_fixture) as client:
        response = await client.get(
            "/api/v1/devices/network-identities",
            headers={
                **_authorization("devices-reader"),
                "X-Correlation-ID": unsafe_correlation,
            },
        )

    assert response.status_code != 422
    assert "X-Correlation-ID" not in response.headers
    assert unsafe_correlation not in response.text


@pytest.mark.asyncio
async def test_same_key_mismatch_returns_409_with_stable_code(
    route_fixture: RouteFixture,
) -> None:
    """Mapping a replay conflict to a generic success would silently change intent."""
    path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        first = await client.post(
            path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
        conflict = await client.post(
            path,
            json={
                **CREATE_BODY,
                "parameters": {"reason": "Different normalized request"},
            },
            headers=_create_headers("creator-old"),
        )

    assert first.status_code == 201
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == (
        "endpoint_operation_idempotency_conflict"
    )


@pytest.mark.asyncio
async def test_route_device_is_never_accepted_from_request_body(
    route_fixture: RouteFixture,
) -> None:
    """A caller-supplied body device must not override the authorized route target."""
    path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    body = {**CREATE_BODY, "device_id": str(route_fixture.other_device.id)}
    async with _client(route_fixture) as client:
        response = await client.post(
            path, json=body, headers=_create_headers("creator-old")
        )

    assert response.status_code == 422
    async with route_fixture.session_provider() as session:
        assert (await session.scalars(select(EndpointOperation))).all() == []


@pytest.mark.asyncio
async def test_read_uses_service_client_identity_across_credential_rotation(
    route_fixture: RouteFixture,
) -> None:
    """Binding reads to the old credential would make safe rotation revoke history."""
    create_path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        created = await client.post(
            create_path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
        operation_id = created.json()["data"]["operation"]["operation_id"]
        read_path = f"/api/v1/operations/{operation_id}"
        unauthenticated = await client.get(read_path)
        wrong_scope = await client.get(read_path, headers=_authorization("creator-old"))
        rotated = await client.get(read_path, headers=_authorization("reader-rotated"))
        foreign = await client.get(read_path, headers=_authorization("foreign-reader"))

    assert created.status_code == 201
    assert unauthenticated.status_code == 401
    assert wrong_scope.status_code == 403
    assert rotated.status_code == 200
    assert foreign.status_code == 404
    assert rotated.json()["data"]["operation"]["operation_id"] == operation_id


@pytest.mark.asyncio
async def test_succeeded_operation_without_safe_result_fails_closed(
    route_fixture: RouteFixture,
) -> None:
    """Availability must never claim a result that cannot pass safe projection."""
    create_path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        created = await client.post(
            create_path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
        operation_id = created.json()["data"]["operation"]["operation_id"]

    async with route_fixture.session_provider() as session:
        operation = await session.get(EndpointOperation, UUID(operation_id))
        assert operation is not None
        operation.status = "succeeded"
        operation.completed_at = datetime.now(UTC)
        operation.context_collection_id = None
        await session.commit()

    async with _client(route_fixture) as client:
        response = await client.get(
            f"/api/v1/operations/{operation_id}",
            headers=_authorization("reader-rotated"),
        )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "endpoint_operation_result_unavailable"
    )
    assert "result_available" not in response.text


@pytest.mark.asyncio
async def test_completed_read_returns_only_validated_safe_result_projection(
    route_fixture: RouteFixture,
) -> None:
    """Raw result, storage, command, and credential internals must never serialize."""
    create_path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        created = await client.post(
            create_path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
        operation_id = created.json()["data"]["operation"]["operation_id"]

    completed_at = datetime.now(UTC)
    async with route_fixture.session_provider() as session:
        operation = await session.get(EndpointOperation, UUID(operation_id))
        assert operation is not None
        collection = await session.get(
            ContextCollection, operation.context_collection_id
        )
        assert collection is not None
        operation.status = "succeeded"
        operation.completed_at = completed_at
        collection.status = "completed"
        collection.completed_at = completed_at
        collection.raw_result_payload = {
            "authorization": "Bearer raw-token-secret",
            "traceback": "C:\\private\\agent.py",
        }
        session.add(
            ContextSnapshot(
                id=uuid4(),
                collection_id=collection.id,
                device_id=route_fixture.device.id,
                profile="diagnostic_v1",
                collected_at=completed_at,
                semantic_hash="a" * 64,
                raw_payload={
                    "command_id": str(uuid4()),
                    "token": "raw-token-secret",
                    "traceback": "/srv/private/agent.py",
                },
                normalized_projection={
                    "schema_version": "device_context_v1",
                    "profile": "diagnostic_v1",
                    "collected_at": completed_at.isoformat(),
                    "warnings": ["redaction_applied"],
                    "sections": {
                        "reason": CREATE_BODY["parameters"]["reason"],
                        "processes": [{"name": "endpoint-agent", "state": "running"}],
                        "log_excerpt": "Bearer authentication was redacted.",
                    },
                },
            )
        )
        await session.commit()

    async with _client(route_fixture) as client:
        response = await client.get(
            f"/api/v1/operations/{operation_id}",
            headers=_authorization("reader-rotated"),
        )

    assert response.status_code == 200
    payload = response.json()["data"]
    assert set(payload["operation"]) == {
        "schema_version",
        "operation_id",
        "device_id",
        "capability",
        "status",
        "created_at",
        "deadline_at",
        "completed_at",
        "result_available",
        "warnings",
    }
    assert payload["operation"]["result_available"] is True
    assert payload["result"] == {
        "schema_version": "endpoint_diagnostic_result_v1",
        "profile": "diagnostic_v1",
        "collected_at": completed_at.isoformat().replace("+00:00", "Z"),
        "reason": "Collect bounded diagnostic context",
        "warnings": ["redaction_applied"],
        "processes": [{"name": "endpoint-agent", "state": "running"}],
        "log_excerpt": "Bearer authentication was redacted.",
    }
    serialized = response.text.lower()
    for forbidden in (
        "raw-token-secret",
        "traceback",
        "private/agent.py",
        "context_collection_id",
        "command_id",
        "idempotency_key",
        "requested_by_service_client_id",
        "credential",
        "session_id",
    ):
        assert forbidden not in serialized


@pytest.mark.asyncio
async def test_public_reason_is_always_derived_from_server_request(
    route_fixture: RouteFixture,
) -> None:
    """Agent output must not replace the safe reason accepted by the server."""
    create_path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        created = await client.post(
            create_path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
    operation_id = created.json()["data"]["operation"]["operation_id"]
    completed_at = datetime.now(UTC)
    await _complete_operation(
        route_fixture,
        operation_id,
        normalized_projection=_diagnostic_projection(
            completed_at=completed_at,
            reason="agent supplied reason with password=super-secret",
        ),
    )

    async with _client(route_fixture) as client:
        response = await client.get(
            f"/api/v1/operations/{operation_id}",
            headers=_authorization("reader-rotated"),
        )

    assert response.status_code == 200
    assert (
        response.json()["data"]["result"]["reason"]
        == (CREATE_BODY["parameters"]["reason"])
    )
    assert "super-secret" not in response.text


@pytest.mark.asyncio
async def test_direct_projection_redacts_secret_after_bearer_marker(
    route_fixture: RouteFixture,
) -> None:
    """A marker prefix must not bless a trailing credential in a process name."""
    create_path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        created = await client.post(
            create_path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
    operation_id = created.json()["data"]["operation"]["operation_id"]
    completed_at = datetime.now(UTC)
    operation, _, snapshot = await _complete_operation(
        route_fixture,
        operation_id,
        normalized_projection=_diagnostic_projection(
            completed_at=completed_at,
            processes=[{"name": "Bearer redacted actual-secret", "state": "running"}],
            log_excerpt=None,
        ),
    )

    result = project_diagnostic_result(operation, snapshot)

    assert result is not None
    assert [process.name for process in result.processes] == ["[REDACTED]"]
    assert "actual-secret" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_actual_agent_diagnostic_is_normalized_to_safe_success(
    route_fixture: RouteFixture,
) -> None:
    """Canonical agent ``<redacted>`` output must remain safely consumable."""

    class DiagnosticProbe:
        platform_name = "linux"

        def run(
            self,
            command: tuple[str, ...],
            _timeout: float,
            _max_output: int,
        ) -> str:
            if command == PROCESS_COMMAND:
                return (
                    "/srv/private/endpoint-agent R\n"
                    "AWS_SECRET_ACCESS_KEY=process-secret R\n"
                    "endpoint-agent S\n"
                )
            if command == JOURNAL_COMMAND:
                return "Authorization: Bearer log-secret token=another-secret"
            raise AssertionError(f"unexpected command: {command!r}")

    create_path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        created = await client.post(
            create_path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
    operation_id = created.json()["data"]["operation"]["operation_id"]
    completed_at = datetime.now(UTC)
    produced = collect_diagnostic(
        DiagnosticProbe(),
        reason=CREATE_BODY["parameters"]["reason"],
        collected_at=completed_at,
    )
    assert "<redacted>" in produced.sections.log_excerpt
    await _complete_operation(
        route_fixture,
        operation_id,
        normalized_projection=produced.model_dump(mode="json"),
    )

    async with _client(route_fixture) as client:
        response = await client.get(
            f"/api/v1/operations/{operation_id}",
            headers=_authorization("reader-rotated"),
        )

    assert response.status_code == 200
    result = response.json()["data"]["result"]
    assert result["reason"] == CREATE_BODY["parameters"]["reason"]
    assert result["log_excerpt"] == "[REDACTED]"
    assert result["processes"] == [
        {"name": "[REDACTED]", "state": "running"},
        {"name": "[REDACTED]", "state": "running"},
        {"name": "endpoint-agent", "state": "sleeping"},
    ]
    serialized = response.text.lower()
    for forbidden in (
        "<redacted>",
        "log-secret",
        "another-secret",
        "process-secret",
        "/srv/private",
    ):
        assert forbidden not in serialized


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "malformation",
    [
        "snapshot_device",
        "snapshot_profile",
        "collection_device",
        "collection_profile",
        "collection_status",
    ],
)
async def test_result_requires_consistent_completed_diagnostic_relationship(
    route_fixture: RouteFixture,
    malformation: str,
) -> None:
    """Cross-device, cross-profile, and inconsistent relationships fail closed."""
    create_path = f"/api/v1/devices/{route_fixture.device.id}/operations"
    async with _client(route_fixture) as client:
        created = await client.post(
            create_path, json=CREATE_BODY, headers=_create_headers("creator-old")
        )
    operation_id = created.json()["data"]["operation"]["operation_id"]
    completed_at = datetime.now(UTC)
    operation, collection, snapshot = await _complete_operation(
        route_fixture,
        operation_id,
        normalized_projection=_diagnostic_projection(completed_at=completed_at),
    )
    async with route_fixture.session_provider() as session:
        persistent_collection = await session.get(ContextCollection, collection.id)
        persistent_snapshot = await session.get(ContextSnapshot, snapshot.id)
        assert persistent_collection is not None
        assert persistent_snapshot is not None
        if malformation == "snapshot_device":
            persistent_snapshot.device_id = route_fixture.other_device.id
        elif malformation == "snapshot_profile":
            persistent_snapshot.profile = "baseline_v1"
        elif malformation == "collection_device":
            persistent_collection.device_id = route_fixture.other_device.id
        elif malformation == "collection_profile":
            persistent_collection.profile = "baseline_v1"
        else:
            persistent_collection.status = "validated"
        await session.commit()

    async with _client(route_fixture) as client:
        response = await client.get(
            f"/api/v1/operations/{operation.id}",
            headers=_authorization("reader-rotated"),
        )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "endpoint_operation_result_unavailable"
    )


def test_enabled_runtime_openapi_exactly_matches_committed_operation_routes(
    route_fixture: RouteFixture,
) -> None:
    """Runtime docs and the published API artifact must describe one boundary."""
    runtime = create_app(
        _settings(enabled=True), route_fixture.session_provider
    ).openapi()
    committed = yaml.safe_load(
        Path("contracts/openapi/endpoint-platform-v1.yaml").read_text(encoding="utf-8")
    )
    operation_paths = (
        "/api/v1/devices/{device_id}",
        "/api/v1/devices/{device_id}/capabilities",
        "/api/v1/devices/{device_id}/operations",
        "/api/v1/operations/{operation_id}",
    )
    assert {path: runtime["paths"][path] for path in operation_paths} == {
        path: committed["paths"][path] for path in operation_paths
    }


def test_operation_openapi_declares_required_correlation_response_headers(
    route_fixture: RouteFixture,
) -> None:
    document = create_app(
        _settings(enabled=True), route_fixture.session_provider
    ).openapi()

    for path, method, response_status in (
        ("/api/v1/devices/{device_id}", "get", "200"),
        ("/api/v1/devices/{device_id}", "get", "401"),
        ("/api/v1/devices/{device_id}", "get", "403"),
        ("/api/v1/devices/{device_id}", "get", "404"),
        ("/api/v1/devices/{device_id}", "get", "422"),
        ("/api/v1/devices/{device_id}/capabilities", "get", "200"),
        ("/api/v1/devices/{device_id}/capabilities", "get", "401"),
        ("/api/v1/devices/{device_id}/capabilities", "get", "403"),
        ("/api/v1/devices/{device_id}/capabilities", "get", "404"),
        ("/api/v1/devices/{device_id}/capabilities", "get", "422"),
        ("/api/v1/devices/{device_id}/operations", "post", "200"),
        ("/api/v1/devices/{device_id}/operations", "post", "201"),
        ("/api/v1/devices/{device_id}/operations", "post", "401"),
        ("/api/v1/devices/{device_id}/operations", "post", "403"),
        ("/api/v1/devices/{device_id}/operations", "post", "409"),
        ("/api/v1/devices/{device_id}/operations", "post", "422"),
        ("/api/v1/devices/{device_id}/operations", "post", "503"),
        ("/api/v1/operations/{operation_id}", "get", "200"),
        ("/api/v1/operations/{operation_id}", "get", "401"),
        ("/api/v1/operations/{operation_id}", "get", "403"),
        ("/api/v1/operations/{operation_id}", "get", "404"),
        ("/api/v1/operations/{operation_id}", "get", "422"),
        ("/api/v1/operations/{operation_id}", "get", "503"),
    ):
        operation = document["paths"][path][method]
        assert any(
            parameter["name"] == "X-Correlation-ID" and parameter["required"]
            for parameter in operation["parameters"]
        )
        assert "X-Correlation-ID" in operation["responses"][response_status]["headers"]
