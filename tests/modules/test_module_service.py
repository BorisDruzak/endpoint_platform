from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from endpoint_server.db.models.modules import (
    ModuleDefinition,
    ModuleLiveTest,
    ModuleValidationRun,
    ModuleVersion,
)
from endpoint_server.db.models.operations import EndpointOperation, ModuleOperationStep
from endpoint_server.modules.service import ModuleServiceError, create_draft_version
from endpoint_server.modules.service import persist_draft_version
from endpoint_server.modules.service import transition_persisted_version
from endpoint_server.modules.service import validate_persisted_module_version
from endpoint_server.modules.service import (
    accept_persisted_module_labs,
    publish_persisted_module_version,
    record_module_live_test,
)


def test_module_service_requires_validated_recipe_before_draft_creation() -> None:
    with pytest.raises(ModuleServiceError, match="recipe"):
        create_draft_version(None)


@pytest.mark.asyncio
async def test_persist_draft_version_reuses_definition_without_committing() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync: ModuleDefinition.metadata.create_all(
                sync,
                tables=(
                    ModuleDefinition.__table__,
                    ModuleVersion.__table__,
                    ModuleValidationRun.__table__,
                ),
            )
        )
    provider = async_sessionmaker(engine, expire_on_commit=False)
    recipe = EndpointRecipeModuleSpecV1.model_validate(
        {
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
        }
    )
    async with provider() as session:
        first = await persist_draft_version(
            session, recipe=recipe, display_name="Network", version="1.0.0"
        )
        second = await persist_draft_version(
            session, recipe=recipe, display_name="Ignored", version="1.0.1"
        )
        assert first.module_definition_id == second.module_definition_id
        persisted_recipe = first.recipe
        await transition_persisted_version(session, first, "validated")
        assert (first.state, first.version, first.recipe) == (
            "validated",
            "1.0.0",
            persisted_recipe,
        )
        assert (
            await session.scalar(select(func.count()).select_from(ModuleDefinition))
            == 1
        )
        with pytest.raises(ModuleServiceError, match="already exists"):
            await persist_draft_version(
                session, recipe=recipe, display_name="Network", version="1.0.1"
            )
        await session.commit()
    await engine.dispose()


@pytest.mark.asyncio
async def test_validation_persists_bounded_evidence_and_transitions_lifecycle() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync: ModuleDefinition.metadata.create_all(
                sync,
                tables=(
                    ModuleDefinition.__table__,
                    ModuleVersion.__table__,
                    ModuleValidationRun.__table__,
                ),
            )
        )
    provider = async_sessionmaker(engine, expire_on_commit=False)
    recipe = EndpointRecipeModuleSpecV1.model_validate(
        {
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
        }
    )
    completed_at = datetime(2026, 8, 26, tzinfo=UTC)
    async with provider() as session:
        valid = await persist_draft_version(
            session, recipe=recipe, display_name="Network", version="1.0.0"
        )
        valid_run = await validate_persisted_module_version(
            session, valid, completed_at=completed_at
        )
        invalid = await persist_draft_version(
            session, recipe=recipe, display_name="Network", version="1.0.1"
        )
        invalid.recipe = {"schema_version": "endpoint_recipe_module_v1"}
        invalid_run = await validate_persisted_module_version(
            session, invalid, completed_at=completed_at
        )

    assert (
        valid.state,
        valid_run.status,
        valid_run.error_codes,
        valid_run.completed_at,
    ) == (
        "validated",
        "succeeded",
        [],
        completed_at,
    )
    assert (invalid.state, invalid_run.status, invalid_run.error_codes) == (
        "validation_failed",
        "failed",
        ["recipe_contract_invalid"],
    )
    await engine.dispose()


@pytest.mark.asyncio
async def test_publication_requires_passed_lab_evidence_for_every_platform() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync: ModuleDefinition.metadata.create_all(
                sync,
                tables=(
                    ModuleDefinition.__table__,
                    ModuleVersion.__table__,
                    ModuleValidationRun.__table__,
                    ModuleLiveTest.__table__,
                    EndpointOperation.__table__,
                    ModuleOperationStep.__table__,
                ),
            )
        )
    provider = async_sessionmaker(engine, expire_on_commit=False)
    recipe = EndpointRecipeModuleSpecV1.model_validate(
        {
            "schema_version": "endpoint_recipe_module_v1",
            "module_key": "network.basic.check",
            "supported_platforms": ["linux_amd64", "windows_amd64"],
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
        }
    )
    tested_at = datetime(2026, 8, 26, tzinfo=UTC)
    async with provider() as session:
        module_version = await persist_draft_version(
            session, recipe=recipe, display_name="Network", version="1.0.0"
        )
        await validate_persisted_module_version(
            session, module_version, completed_at=tested_at
        )
        with pytest.raises(ModuleServiceError, match="lab"):
            await accept_persisted_module_labs(session, module_version)

        async def record_passed_lab(
            platform: str, *, expected_step_count: int = 1
        ) -> None:
            device_id = uuid4()
            operation = EndpointOperation(
                id=uuid4(),
                created_at=tested_at,
                requested_by_service_client_id=uuid4(),
                device_id=device_id,
                idempotency_key=f"module-lab-{platform}",
                capability="endpoint.module.recipe",
                parameters={
                    "execution_mode": "lab",
                    "execution_platform": platform,
                },
                correlation=None,
                status="succeeded",
                deadline_at=tested_at + timedelta(seconds=90),
                completed_at=tested_at,
                context_collection_id=None,
                command_id=None,
                module_version_id=module_version.id,
                module_inputs={"target": "endpoint-staging.sosnadmin.local"},
                expected_step_count=expected_step_count,
            )
            session.add(operation)
            session.add(
                ModuleOperationStep(
                    id=uuid4(),
                    created_at=tested_at,
                    operation_id=operation.id,
                    sequence=0,
                    recipe_step_key="dns",
                    capability="dns.resolve",
                    status="succeeded",
                    command_id=None,
                    safe_result_json={"status": "succeeded"},
                    error_code=None,
                    started_at=tested_at,
                    completed_at=tested_at,
                )
            )
            await session.flush()
            await record_module_live_test(
                session,
                module_version,
                operation_id=operation.id,
                tested_at=tested_at,
            )

        with pytest.raises(ModuleServiceError, match="steps"):
            await record_passed_lab("linux_amd64", expected_step_count=2)
        await record_passed_lab("linux_amd64")
        with pytest.raises(ModuleServiceError, match="lab"):
            await accept_persisted_module_labs(session, module_version)
        await record_passed_lab("windows_amd64")
        accepted = await accept_persisted_module_labs(session, module_version)
        assert accepted.state == "lab_accepted"
        published = await publish_persisted_module_version(session, module_version)

    assert published.state == "published"
    await engine.dispose()


@pytest.mark.asyncio
async def test_live_test_rejects_an_operation_not_owned_by_the_module_version() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync: ModuleDefinition.metadata.create_all(
                sync,
                tables=(
                    ModuleDefinition.__table__,
                    ModuleVersion.__table__,
                    ModuleValidationRun.__table__,
                    ModuleLiveTest.__table__,
                    EndpointOperation.__table__,
                ),
            )
        )
    provider = async_sessionmaker(engine, expire_on_commit=False)
    recipe = EndpointRecipeModuleSpecV1.model_validate(
        {
            "schema_version": "endpoint_recipe_module_v1",
            "module_key": "network.basic.check",
            "supported_platforms": ["windows_amd64"],
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
        }
    )
    async with provider() as session:
        version = await persist_draft_version(
            session, recipe=recipe, display_name="Network", version="1.0.0"
        )
        await validate_persisted_module_version(session, version)
        with pytest.raises(ModuleServiceError, match="operation"):
            await record_module_live_test(
                session,
                version,
                operation_id=uuid4(),
            )
    await engine.dispose()
