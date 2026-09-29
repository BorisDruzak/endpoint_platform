"""Possession challenges are independent of user authentication and enrollment."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.db.models import Device


@pytest.fixture
async def sessions():
    from endpoint_server.db.models import DeviceBindingChallenge, DeviceBindingThrottle
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(lambda sync: Device.metadata.create_all(sync, tables=[
            Device.__table__, DeviceBindingChallenge.__table__, DeviceBindingThrottle.__table__]))
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def new_device(sessions):
    async with sessions() as session:
        device = Device(id=uuid4(), device_identifier=uuid4().hex, display_name="PC")
        session.add(device)
        await session.commit()
        return device


@pytest.mark.asyncio
async def test_challenge_replacement_ttl_and_secret_storage(sessions):
    from endpoint_server.device_binding.service import create_challenge, code_digest
    from endpoint_server.db.models import DeviceBindingChallenge
    device = await new_device(sessions)
    now = datetime.now(UTC)
    async with sessions() as session:
        first = await create_challenge(session, device.id, b"test-pepper", now=now)
        await session.commit()
        second = await create_challenge(session, device.id, b"test-pepper", now=now+timedelta(seconds=1))
        await session.commit()
        records = (await session.scalars(select(DeviceBindingChallenge))).all()
        assert [record.status for record in records].count("active") == 1
        assert next(r for r in records if r.id == first.challenge_id).status == "revoked"
        assert second.expires_in_seconds == 600
        assert second.expires_at == now+timedelta(seconds=601)
        assert second.code.isascii() and second.code.isdigit() and len(second.code) == 6
        assert second.display_code == second.code[:3]+"-"+second.code[3:]
        active = next(r for r in records if r.status == "active")
        assert active.code_digest == code_digest(second.code, b"test-pepper")
        assert second.code not in repr(second)
        assert "code" not in DeviceBindingChallenge.__table__.columns


@pytest.mark.asyncio
async def test_redeem_is_single_use_and_expired_revoked_invalid_are_uniform(sessions):
    from endpoint_server.device_binding.service import create_challenge, redeem_challenge, ChallengeUnavailable
    device = await new_device(sessions)
    now = datetime.now(UTC)
    async with sessions() as session:
        first = await create_challenge(session, device.id, b"pepper", now=now)
        await session.commit()
        verified = await redeem_challenge(session, first.code, b"pepper", now=now)
        assert verified == device.id
        await session.commit()
        with pytest.raises(ChallengeUnavailable, match="Challenge unavailable"):
            await redeem_challenge(session, first.code, b"pepper", now=now)
        expired = await create_challenge(session, device.id, b"pepper", now=now)
        await session.commit()
        with pytest.raises(ChallengeUnavailable, match="Challenge unavailable"):
            await redeem_challenge(session, expired.code, b"pepper", now=now+timedelta(seconds=600))
        await session.commit()
        with pytest.raises(ChallengeUnavailable, match="Challenge unavailable"):
            await redeem_challenge(session, "not-a-code", b"pepper", now=now)


@pytest.mark.asyncio
async def test_attempt_budget_survives_new_session(sessions):
    from endpoint_server.device_binding.service import consume_budget, ChallengeThrottled
    now = datetime.now(UTC)
    for _ in range(5):
        async with sessions() as session:
            await consume_budget(session, "service:test", limit=5, window_seconds=600, now=now)
            await session.commit()
    async with sessions() as session:
        with pytest.raises(ChallengeThrottled):
            await consume_budget(session, "service:test", limit=5, window_seconds=600, now=now)
        await consume_budget(session, "service:test", limit=5, window_seconds=600, now=now+timedelta(seconds=600))
        await session.commit()


def test_contract_rejects_arbitrary_device_and_hides_code_repr():
    from pydantic import ValidationError
    from endpoint_contracts.device_binding import DeviceBindingCreateV1, DeviceBindingRedeemV1
    with pytest.raises(ValidationError):
        DeviceBindingCreateV1(purpose="helpdesk_device_binding", device_id=uuid4())
    body = DeviceBindingRedeemV1(purpose="helpdesk_device_binding", code="123456")
    assert body.code not in repr(body)
    for code in ("１２３４５６", "123-456", "12345", "1234567"):
        with pytest.raises(ValidationError):
            DeviceBindingRedeemV1(purpose="helpdesk_device_binding", code=code)


@pytest.mark.asyncio
async def test_recent_redeemed_code_cannot_verify_a_different_device(sessions, monkeypatch):
    from endpoint_server.device_binding import service
    first_device = await new_device(sessions)
    second_device = await new_device(sessions)
    now = datetime.now(UTC)
    values = iter([123456, 123456, 234567])
    monkeypatch.setattr(service.secrets, "randbelow", lambda _:next(values))
    async with sessions() as session:
        first = await service.create_challenge(session, first_device.id, b"pepper", now=now)
        await session.commit()
        await service.redeem_challenge(session, first.code, b"pepper", now=now)
        await session.commit()
        second = await service.create_challenge(session, second_device.id, b"pepper", now=now)
        assert second.code != first.code


@pytest.mark.asyncio
async def test_redemption_rechecks_ttl_after_namespace_lock_wait(sessions, monkeypatch):
    from endpoint_server.device_binding import service
    device = await new_device(sessions)
    issued_at = datetime.now(UTC)
    async with sessions() as session:
        proof = await service.create_challenge(session, device.id, b"pepper", now=issued_at)
        await session.commit()
        clock = [issued_at + timedelta(seconds=599)]
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None): return clock[0]
        original_budget = service.consume_budget
        async def lock_wait(*args, **kwargs):
            await original_budget(*args, **kwargs)
            clock[0] = issued_at + timedelta(seconds=601)
        monkeypatch.setattr(service, "datetime", Clock)
        monkeypatch.setattr(service, "consume_budget", lock_wait)
        with pytest.raises(service.ChallengeUnavailable):
            await service.redeem_challenge(session, proof.code, b"pepper")
