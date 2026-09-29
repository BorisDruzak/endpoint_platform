"""Transactional possession proof lifecycle and durable short-code budgets."""
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import re
import secrets
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.device_binding import DeviceBindingChallengeV1
from endpoint_server.db.models import Device, DeviceBindingChallenge, DeviceBindingThrottle

PURPOSE = "helpdesk_device_binding"
TTL_SECONDS = 600


class ChallengeUnavailable(RuntimeError):
    def __init__(self, *, expired: tuple[UUID, UUID] | None = None):
        self.expired = expired
        super().__init__("Challenge unavailable")


class ChallengeThrottled(RuntimeError):
    def __init__(self):
        super().__init__("Challenge request throttled")


def code_digest(code: str, pepper: bytes) -> str:
    if not pepper or not re.fullmatch(r"[0-9]{6}", code):
        raise ChallengeUnavailable()
    return hmac.new(pepper, b"endpoint:helpdesk-device-binding:v1\0"+code.encode("ascii"), hashlib.sha256).hexdigest()


def _utc(value: datetime) -> datetime:
    # SQLite tests lose timezone information; PostgreSQL preserves UTC.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def consume_budget(session: AsyncSession, bucket: str, *, limit: int,
                         window_seconds: int, now: datetime | None = None,
                         consume: bool = True) -> None:
    checked_at = now or datetime.now(UTC)
    statement = select(DeviceBindingThrottle).where(DeviceBindingThrottle.bucket == bucket).with_for_update()
    record = await session.scalar(statement)
    if record is None:
        try:
            async with session.begin_nested():
                session.add(DeviceBindingThrottle(bucket=bucket, window_started_at=checked_at, attempts=0))
                await session.flush()
        except IntegrityError:
            # A concurrent first attempt inserted the bucket. Lock its committed row.
            pass
        record = await session.scalar(statement.execution_options(populate_existing=True))
    if record is None:
        raise ChallengeUnavailable()
    if checked_at >= _utc(record.window_started_at)+timedelta(seconds=window_seconds):
        record.window_started_at, record.attempts = checked_at, 0
    if record.attempts >= limit:
        raise ChallengeThrottled()
    if consume:
        record.attempts += 1
    await session.flush()


async def create_challenge(session: AsyncSession, device_id: UUID, pepper: bytes,
                           *, now: datetime | None = None,
                           lifecycle_events: list[tuple[UUID, str]] | None = None) -> DeviceBindingChallengeV1:
    issued_at = now or datetime.now(UTC)
    # Serialize the small shared code namespace with redemptions too. This
    # prevents reissuing a just-redeemed code while its original TTL remains.
    await consume_budget(session, "binding:namespace", limit=120, window_seconds=60, now=issued_at)
    device = await session.scalar(select(Device).where(Device.id == device_id, Device.retired_at.is_(None)).with_for_update())
    if device is None:
        raise ChallengeUnavailable()
    issued_at = now if now is not None else datetime.now(UTC)
    previous = (await session.scalars(select(DeviceBindingChallenge).where(
        DeviceBindingChallenge.device_id == device_id, DeviceBindingChallenge.purpose == PURPOSE,
        DeviceBindingChallenge.status == "active").with_for_update())).all()
    for record in previous:
        record.status = "expired" if _utc(record.expires_at) <= issued_at else "revoked"
        if lifecycle_events is not None:
            lifecycle_events.append((record.id, record.status))
    await session.flush()
    for _ in range(32):
        code = f"{secrets.randbelow(1_000_000):06d}"
        digest = code_digest(code, pepper)
        recent = await session.scalar(select(DeviceBindingChallenge.id).where(
            DeviceBindingChallenge.code_digest == digest,
            DeviceBindingChallenge.expires_at > issued_at).limit(1))
        if recent is not None:
            continue
        record = DeviceBindingChallenge(id=uuid4(), device_id=device_id, purpose=PURPOSE,
            code_digest=digest, status="active", created_at=issued_at,
            expires_at=issued_at+timedelta(seconds=TTL_SECONDS))
        try:
            async with session.begin_nested():
                session.add(record)
                await session.flush()
        except IntegrityError:
            continue
        return DeviceBindingChallengeV1(challenge_id=record.id, code=code,
            display_code=code[:3]+"-"+code[3:], expires_at=record.expires_at,
            expires_in_seconds=TTL_SECONDS)
    raise ChallengeUnavailable()


async def redeem_challenge(session: AsyncSession, code: str, pepper: bytes,
                           *, now: datetime | None = None) -> UUID:
    checked_at = now or datetime.now(UTC)
    digest = code_digest(code, pepper)
    await consume_budget(session, "binding:namespace", limit=120, window_seconds=60, now=checked_at)
    # A request can wait across expiry while another transaction owns the
    # namespace. TTL is checked at consumption, not at request arrival.
    checked_at = now if now is not None else datetime.now(UTC)
    # Conditional UPDATE (not read/then/write) gives one winner even if two
    # requests read the same snapshot. A losing update returns no identity.
    device_id = await session.scalar(update(DeviceBindingChallenge).where(
        DeviceBindingChallenge.code_digest == digest,
        DeviceBindingChallenge.purpose == PURPOSE,
        DeviceBindingChallenge.status == "active",
        DeviceBindingChallenge.expires_at > checked_at,
        DeviceBindingChallenge.device_id.in_(select(Device.id).where(Device.retired_at.is_(None))),
    ).values(status="redeemed", redeemed_at=checked_at).returning(DeviceBindingChallenge.device_id))
    if device_id is None:
        expired = (await session.execute(update(DeviceBindingChallenge).where(
            DeviceBindingChallenge.code_digest == digest,
            DeviceBindingChallenge.status == "active",
            DeviceBindingChallenge.expires_at <= checked_at,
        ).values(status="expired").returning(DeviceBindingChallenge.id, DeviceBindingChallenge.device_id))).first()
        raise ChallengeUnavailable(expired=tuple(expired) if expired else None)
    return device_id
