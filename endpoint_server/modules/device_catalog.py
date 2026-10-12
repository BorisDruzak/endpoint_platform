"""Shared published query and compatibility projection; no authoring privilege."""
import base64
import hmac
import json
from datetime import UTC, datetime
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import and_, or_, select

from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY
from endpoint_contracts.device_modules import EndpointDeviceModulesPageV1, PublishedDeviceModuleV1
from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from endpoint_server.db.models import Device, ModuleDefinition, ModuleVersion
from endpoint_server.operations.capabilities import module_capability_incompatibility_code
from .recipes import validate_recipe_spec


class InvalidModuleCursor(ValueError):
    pass


class CatalogDeviceNotFound(ValueError):
    pass


def published_module_query():
    return (select(ModuleDefinition, ModuleVersion)
        .join(ModuleVersion, ModuleVersion.module_definition_id == ModuleDefinition.id)
        .where(ModuleVersion.state == "published")
        .order_by(ModuleDefinition.module_key, ModuleVersion.created_at, ModuleVersion.id))


def project_published_module(settings, connection, definition, version):
    try:
        recipe = EndpointRecipeModuleSpecV1.model_validate(version.recipe)
        validate_recipe_spec(recipe)
        if recipe.module_key != definition.module_key:
            raise ValueError("mismatched module")
    except (ValidationError, ValueError):
        recipe = None
    reason = None
    availability = "available"
    if recipe is None:
        reason = "invalid_recipe"
        availability = "unknown"
    elif connection is None:
        reason = "device_offline"
    elif not connection.platform or not connection.agent_version:
        reason = "agent_facts_missing"
        availability = "unknown"
    elif connection.platform not in recipe.supported_platforms:
        reason = "platform_unsupported"
    else:
        for step in recipe.steps:
            reason = module_capability_incompatibility_code(settings, connection, MODULE_CAPABILITY_REGISTRY[step.capability])
            if reason:
                break
    if reason and availability == "available":
        availability = "unavailable"
    return PublishedDeviceModuleV1(module_key=definition.module_key, display_name=definition.display_name,
        version=version.version, recipe=recipe, availability=availability, reason_code=reason)


def _decode_cursor(cursor, secret, device_id):
    try:
        if len(cursor) > 1024:
            raise ValueError()
        raw = base64.b64decode(cursor, altchars=b"-_", validate=True)
        payload, signature = raw[:-32], raw[-32:]
        if not hmac.compare_digest(signature, hmac.digest(secret, b"device-modules-v1\0" + payload, "sha256")):
            raise ValueError()
        device, key, created, identifier = json.loads(payload)
        if device != str(device_id) or not isinstance(key, str) or len(key) > 128:
            raise ValueError()
        return key, datetime.fromisoformat(created), UUID(identifier)
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidModuleCursor("invalid device catalog cursor") from error


def _encode_cursor(version, definition, secret, device_id):
    payload = json.dumps([str(device_id), definition.module_key, version.created_at.isoformat(), str(version.id)],
        separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload + hmac.digest(secret, b"device-modules-v1\0" + payload, "sha256")).decode()


async def project_device_modules(session, settings, connection, device_id, limit=50, cursor=None):
    if not 1 <= limit <= 100:
        raise ValueError("limit outside 1..100")
    if await session.scalar(select(Device.id).where(Device.id == device_id, Device.retired_at.is_(None))) is None:
        raise CatalogDeviceNotFound()
    query = published_module_query()
    if cursor is not None:
        key, created, identifier = _decode_cursor(cursor, settings.session_secret, device_id)
        query = query.where(or_(ModuleDefinition.module_key > key,
            and_(ModuleDefinition.module_key == key, ModuleVersion.created_at > created),
            and_(ModuleDefinition.module_key == key, ModuleVersion.created_at == created, ModuleVersion.id > identifier)))
    rows = (await session.execute(query.limit(limit + 1))).all()
    page_rows = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        definition, version = page_rows[-1]
        next_cursor = _encode_cursor(version, definition, settings.session_secret, device_id)
    return EndpointDeviceModulesPageV1(device_id=device_id, observed_at=datetime.now(UTC),
        items=[project_published_module(settings, connection, definition, version) for definition, version in page_rows],
        next_cursor=next_cursor)
