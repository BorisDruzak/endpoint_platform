"""One-use assignment authority for the reserved inventory enrollment namespace."""

from datetime import UTC, datetime, timedelta
import hmac
import re

from sqlalchemy import select

from endpoint_server.db.models import InventoryInstallationAssignment

from .campaigns import EnrollmentDenied, hardware_fingerprint_digest
from .requests import installation_id_digest


INVENTORY_PREFIX = "inventory-"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
INSTALLATION_ID_PATTERN = re.compile(rf"^{INVENTORY_PREFIX}{_UUID}-{_UUID}-[0-9a-f]{{32}}$")
ASSIGNMENT_LIFETIME = timedelta(minutes=30)


def utc(timestamp: datetime) -> datetime:
    return timestamp.astimezone(UTC) if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)


async def load_inventory_assignment(session, *, installation_id, hardware_fingerprint, platform, pepper, lock=False):
    """Resolve a live, hardware-bound assignment for the reserved namespace."""
    if not installation_id.startswith(INVENTORY_PREFIX):
        return None
    statement = select(InventoryInstallationAssignment).where(
        InventoryInstallationAssignment.installation_digest == installation_id_digest(installation_id, pepper),
    )
    if lock:
        statement = statement.with_for_update()
    row = (await session.execute(statement)).scalar_one_or_none()
    if (
        row is None
        or utc(row.expires_at) <= datetime.now(UTC)
        or row.platform != platform
        or not hmac.compare_digest(row.fingerprint_digest, hardware_fingerprint_digest(hardware_fingerprint, pepper))
    ):
        raise EnrollmentDenied("Inventory assignment is unavailable")
    return row


async def bind_inventory_assignment(session, record, *, installation_id, hardware_fingerprint, pepper):
    """Pin the first eligible claim request inside the caller's transaction."""
    row = await load_inventory_assignment(
        session, installation_id=installation_id, hardware_fingerprint=hardware_fingerprint,
        platform=record.platform, pepper=pepper, lock=True,
    )
    if row is None:
        return None
    if utc(record.created_at) < utc(row.issued_at) or row.enrollment_request_id not in (None, record.id):
        raise EnrollmentDenied("Inventory assignment is unavailable")
    row.enrollment_request_id = record.id
    return utc(row.expires_at)


async def require_inventory_claim(session, claim, *, installation_id, hardware_fingerprint, platform, pepper):
    """Enforce the pinned request for agent delivery, including campaign bearer paths."""
    if not installation_id.startswith(INVENTORY_PREFIX):
        return
    if claim is None or claim.enrollment_request_id is None:
        raise EnrollmentDenied("Inventory assignment is unavailable")
    row = await load_inventory_assignment(
        session, installation_id=installation_id, hardware_fingerprint=hardware_fingerprint,
        platform=platform, pepper=pepper,
    )
    if row.enrollment_request_id != claim.enrollment_request_id:
        raise EnrollmentDenied("Inventory assignment is unavailable")
    return row
