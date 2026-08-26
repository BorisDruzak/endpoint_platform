from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from endpoint_server.db.models.modules import (
    ModuleDefinition,
    ModuleValidationRun,
    ModuleVersion,
)
from endpoint_server.modules.service import ModuleServiceError, create_draft_version
from endpoint_server.modules.service import persist_draft_version
from endpoint_server.modules.service import transition_persisted_version
from endpoint_server.modules.service import validate_persisted_module_version


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
    recipe = EndpointRecipeModuleSpecV1.model_validate({"schema_version":"endpoint_recipe_module_v1","module_key":"network.basic.check","supported_platforms":["linux_amd64"],"inputs":[{"name":"target","value_type":"string"}],"steps":[{"step_id":"dns","capability":"dns.resolve","parameters":{"target":{"kind":"input","name":"target"},"family":{"kind":"literal","value":"any"}}}]})
    async with provider() as session:
        first = await persist_draft_version(session, recipe=recipe, display_name="Network", version="1.0.0")
        second = await persist_draft_version(session, recipe=recipe, display_name="Ignored", version="1.0.1")
        assert first.module_definition_id == second.module_definition_id
        persisted_recipe = first.recipe
        await transition_persisted_version(session, first, "validated")
        assert (first.state, first.version, first.recipe) == ("validated", "1.0.0", persisted_recipe)
        assert await session.scalar(select(func.count()).select_from(ModuleDefinition)) == 1
        with pytest.raises(ModuleServiceError, match="already exists"):
            await persist_draft_version(session, recipe=recipe, display_name="Network", version="1.0.1")
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
    recipe = EndpointRecipeModuleSpecV1.model_validate({"schema_version":"endpoint_recipe_module_v1","module_key":"network.basic.check","supported_platforms":["linux_amd64"],"inputs":[{"name":"target","value_type":"string"}],"steps":[{"step_id":"dns","capability":"dns.resolve","parameters":{"target":{"kind":"input","name":"target"},"family":{"kind":"literal","value":"any"}}}]})
    completed_at = datetime(2026, 8, 26, tzinfo=UTC)
    async with provider() as session:
        valid = await persist_draft_version(session, recipe=recipe, display_name="Network", version="1.0.0")
        valid_run = await validate_persisted_module_version(session, valid, completed_at=completed_at)
        invalid = await persist_draft_version(session, recipe=recipe, display_name="Network", version="1.0.1")
        invalid.recipe = {"schema_version": "endpoint_recipe_module_v1"}
        invalid_run = await validate_persisted_module_version(session, invalid, completed_at=completed_at)

    assert (valid.state, valid_run.status, valid_run.error_codes, valid_run.completed_at) == (
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
