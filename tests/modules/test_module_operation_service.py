from __future__ import annotations

from datetime import UTC, datetime
import json
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from endpoint_server.db.models import AuditEvent, Device, EndpointOperation, ServiceClient
from endpoint_server.db.models.modules import ModuleDefinition, ModuleVersion
from endpoint_server.db.models.operations import ModuleOperationStep
from endpoint_server.modules.operation_service import (
    ModuleOperationConflict,
    create_module_parent_operation,
)
from endpoint_server.policy.network_targets import NetworkTargetPolicyV1


def _recipe() -> EndpointRecipeModuleSpecV1:
    return EndpointRecipeModuleSpecV1.model_validate(
        {
            "schema_version": "endpoint_recipe_module_v1",
            "module_key": "network.basic.check",
            "supported_platforms": ["linux_amd64"],
            "inputs": [
                {"name": "target", "value_type": "string"},
                {"name": "port", "value_type": "integer"},
            ],
            "steps": [
                {
                    "step_id": "dns",
                    "capability": "dns.resolve",
                    "parameters": {
                        "target": {"kind": "input", "name": "target"},
                        "family": {"kind": "literal", "value": "any"},
                    },
                },
                {
                    "step_id": "tcp",
                    "capability": "tcp.connect",
                    "parameters": {
                        "target": {"kind": "input", "name": "target"},
                        "port": {"kind": "input", "name": "port"},
                        "timeout_ms": {"kind": "literal", "value": 1000},
                    },
                },
            ],
        }
    )


@pytest.mark.asyncio
async def test_module_parent_operation_is_idempotent_and_materializes_queued_steps() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = (
        ServiceClient.__table__,
        Device.__table__,
        AuditEvent.__table__,
        ModuleDefinition.__table__,
        ModuleVersion.__table__,
        EndpointOperation.__table__,
        ModuleOperationStep.__table__,
    )
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync: Device.metadata.create_all(sync, tables=tables))
    provider = async_sessionmaker(engine, expire_on_commit=False)
    client = ServiceClient(id=uuid4(), client_identifier="helpdesk", display_name="Helpdesk", disabled_at=None)
    device = Device(id=uuid4(), device_identifier="module-device", display_name="Module device", retired_at=None)
    definition = ModuleDefinition(id=uuid4(), module_key="network.basic.check", display_name="Network")
    version = ModuleVersion(
        id=uuid4(),
        module_definition_id=definition.id,
        version="1.0.0",
        recipe=_recipe().model_dump(mode="json"),
        state="published",
    )
    policy = NetworkTargetPolicyV1.from_values(allowed_cidrs=[], allowed_suffixes=[".example.test"])
    now = datetime(2026, 8, 26, tzinfo=UTC)
    async with provider() as session:
        session.add_all((client, device, definition, version))
        await session.flush()
        operation, created = await create_module_parent_operation(
            session,
            service_client_id=client.id,
            device_id=device.id,
            module_key=definition.module_key,
            version="1.0.0",
            inputs={"target": "api.example.test", "port": 443},
            idempotency_key="module-operation-key-0001",
            network_policy=policy,
            now=now,
        )
        replay, replay_created = await create_module_parent_operation(
            session,
            service_client_id=client.id,
            device_id=device.id,
            module_key=definition.module_key,
            version="1.0.0",
            inputs={"target": "api.example.test", "port": 443},
            idempotency_key="module-operation-key-0001",
            network_policy=policy,
            now=now,
        )
        with pytest.raises(ModuleOperationConflict):
            await create_module_parent_operation(
                session,
                service_client_id=client.id,
                device_id=device.id,
                module_key=definition.module_key,
                version="1.0.0",
                inputs={"target": "api.example.test", "port": 8443},
                idempotency_key="module-operation-key-0001",
                network_policy=policy,
                now=now,
            )
        steps = list(
            (await session.scalars(select(ModuleOperationStep).order_by(ModuleOperationStep.sequence))).all()
        )
        audit = await session.scalar(select(AuditEvent))

    assert created is True
    assert replay_created is False
    assert replay.id == operation.id
    assert operation.capability == "endpoint.module.recipe"
    assert operation.module_version_id == version.id
    assert operation.module_inputs == {"target": "api.example.test", "port": 443}
    assert [(step.sequence, step.recipe_step_key, step.capability, step.status) for step in steps] == [
        (0, "dns", "dns.resolve", "queued"),
        (1, "tcp", "tcp.connect", "queued"),
    ]
    assert audit is not None
    assert (audit.action, audit.actor_kind, audit.actor_identifier) == (
        "endpoint.module_operation_created",
        "service",
        "helpdesk",
    )
    assert "api.example.test" not in json.dumps(audit.details)
    await engine.dispose()
